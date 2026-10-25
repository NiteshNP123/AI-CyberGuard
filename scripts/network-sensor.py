"""
AI CyberGuard — Windows Network Flow Sensor
============================================
Captures real TCP/UDP packets on the authorized local interface using Scapy
(which requires Npcap on Windows).

Stateful Flow Lifecycle & Feature Extraction:
- Flow direction is determined by connection initiator (initial SYN packet),
  not lexicographical IP ordering.
- Server service port is preserved as the destination port (dstPort), ensuring
  accurate standard/ephemeral port features for the ML model.
- Stateful lifecycle: connection closure on TCP FIN handshake, RST abortion,
  and protocol-specific idle timeouts (default 15s TCP, 10s UDP).
- Strict 15-feature alignment with CIC-IDS2017 model feature schema.
- Flow duration reported in milliseconds; byte/packet rates computed using
  exact model formulas.
- Zero payload content inspected, captured, or transmitted.

Usage:
  python scripts/network-sensor.py [--iface <interface>] [--api http://127.0.0.1:5000]
"""

import argparse
import logging
import os
import sys
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENSOR] %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("network-sensor")

# ---------------------------------------------------------------------------
# Constants & Contracts
# ---------------------------------------------------------------------------

STANDARD_PORTS = {80, 443, 53, 22, 21, 25, 110, 143, 389, 636, 8080}

FLOW_FEATURES = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "byte_rate",
    "packet_rate",
    "syn_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "ack_flag_count",
    "psh_flag_count",
    "urg_flag_count",
    "dst_port_standard",
    "dst_port_ephemeral"
]

DEFAULT_TCP_IDLE_TIMEOUT = 15.0  # seconds
DEFAULT_UDP_IDLE_TIMEOUT = 10.0  # seconds
DEFAULT_ACTIVE_TIMEOUT = 120.0   # seconds


# ---------------------------------------------------------------------------
# Packet & Flow Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ParsedPacket:
    """Normalized, transport-independent representation of an IP packet."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str       # 'TCP', 'UDP', 'OTHER'
    length: int
    timestamp: float    # Monotonic or epoch seconds
    syn: bool = False
    fin: bool = False
    rst: bool = False
    ack: bool = False
    psh: bool = False
    urg: bool = False


@dataclass(frozen=True)
class ConversationKey:
    """Canonical bidirectional lookup key invariant to packet direction."""
    endpoint_a: Tuple[str, int]
    endpoint_b: Tuple[str, int]
    protocol: str

    @staticmethod
    def from_packet(pkt: ParsedPacket) -> "ConversationKey":
        ep1 = (pkt.src_ip, pkt.src_port)
        ep2 = (pkt.dst_ip, pkt.dst_port)
        if ep1 <= ep2:
            return ConversationKey(ep1, ep2, pkt.protocol)
        return ConversationKey(ep2, ep1, pkt.protocol)


@dataclass
class StatefulFlow:
    """
    Accumulates bidirectional flow telemetry oriented from connection initiator
    (client) to responder (server).
    """
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    protocol: str
    start_time: float
    last_time: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_flags: int = 0
    fin_flags: int = 0
    rst_flags: int = 0
    ack_flags: int = 0
    psh_flags: int = 0
    urg_flags: int = 0
    fin_seen_fwd: bool = False
    fin_seen_bwd: bool = False
    state: str = "NEW"
    is_terminated: bool = False
    termination_reason: Optional[str] = None

    @property
    def duration_ms(self) -> float:
        """Flow duration in milliseconds."""
        return max(0.001, (self.last_time - self.start_time) * 1000.0)

    def calculate_rates(self) -> Tuple[float, float]:
        """
        Derives byte_rate and packet_rate using exact zero-duration protection
        matching model training and inference.
        """
        dur_sec = max(self.duration_ms / 1000.0, 0.001)
        byte_rate = (self.fwd_bytes + self.bwd_bytes) / dur_sec
        packet_rate = (self.fwd_packets + self.bwd_packets) / dur_sec
        return byte_rate, packet_rate

    def to_api_payload(self) -> Dict[str, Any]:
        """Formats flow telemetry for ingestion at /api/network/telemetry."""
        return {
            "srcIp": self.initiator_ip,
            "dstIp": self.responder_ip,
            "srcPort": self.initiator_port,
            "dstPort": self.responder_port,
            "protocol": self.protocol,
            "flowDurationMs": round(self.duration_ms, 3),
            "totalFwdPackets": self.fwd_packets,
            "totalBwdPackets": self.bwd_packets,
            "totalFwdBytes": self.fwd_bytes,
            "totalBwdBytes": self.bwd_bytes,
            "synFlags": self.syn_flags,
            "finFlags": self.fin_flags,
            "rstFlags": self.rst_flags,
            "ackFlags": self.ack_flags,
            "pshFlags": self.psh_flags,
            "urgFlags": self.urg_flags,
            "sensorPipeline": "stateful_initiator_v2"
        }

    def to_feature_vector(self) -> List[float]:
        """
        Constructs the exact 15 normalized flow features matching candidate model.
        """
        byte_rate, packet_rate = self.calculate_rates()
        std_port = 1.0 if self.responder_port in STANDARD_PORTS else 0.0
        eph_port = 1.0 if self.responder_port > 1024 else 0.0

        return [
            float(self.duration_ms),
            float(self.fwd_packets),
            float(self.bwd_packets),
            float(self.fwd_bytes),
            float(self.bwd_bytes),
            float(byte_rate),
            float(packet_rate),
            float(self.syn_flags),
            float(self.fin_flags),
            float(self.rst_flags),
            float(self.ack_flags),
            float(self.psh_flags),
            float(self.urg_flags),
            float(std_port),
            float(eph_port)
        ]


# ---------------------------------------------------------------------------
# Stateful Flow Tracker Engine
# ---------------------------------------------------------------------------

class StatefulFlowTracker:
    """
    Tracks and manages concurrent stateful network flows.
    Determines flow direction by initiator, accumulates directional metrics,
    and handles stateful connection closure and timeouts.
    """

    def __init__(
        self,
        tcp_idle_timeout: float = DEFAULT_TCP_IDLE_TIMEOUT,
        udp_idle_timeout: float = DEFAULT_UDP_IDLE_TIMEOUT,
        active_timeout: float = DEFAULT_ACTIVE_TIMEOUT
    ):
        self.tcp_idle_timeout = tcp_idle_timeout
        self.udp_idle_timeout = udp_idle_timeout
        self.active_timeout = active_timeout
        self._flows: Dict[ConversationKey, StatefulFlow] = {}
        self._lock = threading.Lock()

    @staticmethod
    def determine_initiator(pkt: ParsedPacket) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """
        Determines the initiator (client) and responder (server).
        Priority:
        1. Initial TCP SYN (SYN=1, ACK=0): sender is initiator.
        2. TCP SYN-ACK (SYN=1, ACK=1): receiver is initiator.
        3. Service port heuristic: ephemeral port is initiator, standard port is responder.
        4. Fallback: first observed packet sender is initiator.
        """
        sender = (pkt.src_ip, pkt.src_port)
        receiver = (pkt.dst_ip, pkt.dst_port)

        if pkt.protocol == "TCP":
            # Initial SYN handshake request
            if pkt.syn and not pkt.ack:
                return sender, receiver
            # SYN-ACK handshake response
            if pkt.syn and pkt.ack:
                return receiver, sender

        # Service port heuristic
        src_std = pkt.src_port in STANDARD_PORTS or pkt.src_port <= 1024
        dst_std = pkt.dst_port in STANDARD_PORTS or pkt.dst_port <= 1024

        if dst_std and not src_std:
            return sender, receiver
        if src_std and not dst_std:
            return receiver, sender

        # Default fallback
        return sender, receiver

    def process_packet(self, pkt: ParsedPacket) -> Optional[StatefulFlow]:
        """
        Processes an inbound packet, updates the matching flow accumulator,
        and returns the flow if it reached immediate termination (e.g. RST or FIN closure).
        """
        key = ConversationKey.from_packet(pkt)
        terminated_flow: Optional[StatefulFlow] = None

        with self._lock:
            flow = self._flows.get(key)

            if flow is None:
                init_ep, resp_ep = self.determine_initiator(pkt)
                flow = StatefulFlow(
                    initiator_ip=init_ep[0],
                    initiator_port=init_ep[1],
                    responder_ip=resp_ep[0],
                    responder_port=resp_ep[1],
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp,
                    last_time=pkt.timestamp
                )
                self._flows[key] = flow

            # Update timing
            flow.last_time = max(flow.last_time, pkt.timestamp)

            # Check packet direction
            is_fwd = (pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port)

            if is_fwd:
                flow.fwd_packets += 1
                flow.fwd_bytes += pkt.length
                if pkt.fin:
                    flow.fin_seen_fwd = True
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += pkt.length
                if pkt.fin:
                    flow.fin_seen_bwd = True

            # Accumulate TCP flag counts across flow
            if pkt.syn: flow.syn_flags += 1
            if pkt.fin: flow.fin_flags += 1
            if pkt.rst: flow.rst_flags += 1
            if pkt.ack: flow.ack_flags += 1
            if pkt.psh: flow.psh_flags += 1
            if pkt.urg: flow.urg_flags += 1

            # Connection state tracking & immediate termination
            if pkt.rst:
                flow.state = "CLOSED"
                flow.is_terminated = True
                flow.termination_reason = "RST_RECEIVED"
                terminated_flow = self._flows.pop(key)

            elif flow.fin_seen_fwd and flow.fin_seen_bwd:
                flow.state = "CLOSED"
                flow.is_terminated = True
                flow.termination_reason = "FIN_HANDSHAKE_COMPLETE"
                terminated_flow = self._flows.pop(key)

        return terminated_flow

    def check_timeouts(self, current_time: float) -> List[StatefulFlow]:
        """
        Scans all active flows for idle timeouts or maximum active duration,
        removes expired flows, and returns them for export.
        """
        expired: List[StatefulFlow] = []

        with self._lock:
            keys_to_remove = []

            for key, flow in self._flows.items():
                idle_limit = self.tcp_idle_timeout if flow.protocol == "TCP" else self.udp_idle_timeout
                time_idle = current_time - flow.last_time
                time_active = current_time - flow.start_time

                if time_idle >= idle_limit:
                    flow.is_terminated = True
                    flow.termination_reason = "IDLE_TIMEOUT"
                    keys_to_remove.append(key)
                elif time_active >= self.active_timeout:
                    flow.is_terminated = True
                    flow.termination_reason = "ACTIVE_TIMEOUT"
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                expired.append(self._flows.pop(key))

        return expired

    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)


# Global tracker instance
_flow_tracker = StatefulFlowTracker()
_export_queue: List[StatefulFlow] = []
_export_queue_lock = threading.Lock()

FLOW_WINDOW_SECONDS = 5  # Exporter polling interval in seconds
API_URL = "http://127.0.0.1:5000"


# ---------------------------------------------------------------------------
# Scapy Packet Capture Callback
# ---------------------------------------------------------------------------

def _on_packet(pkt):
    """Callback executed by Scapy sniffer for each live captured packet."""
    try:
        from scapy.layers.inet import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        pkt_len = len(pkt)
        pkt_time = float(getattr(pkt, "time", time.monotonic()))

        syn = fin = rst = ack = psh = urg = False

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags = int(tcp.flags)
            if flags & 0x02: syn = True
            if flags & 0x01: fin = True
            if flags & 0x04: rst = True
            if flags & 0x10: ack = True
            if flags & 0x08: psh = True
            if flags & 0x20: urg = True
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            proto = "UDP"
        else:
            proto = "OTHER"
            src_port = 0
            dst_port = 0

        parsed = ParsedPacket(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=pkt_len,
            timestamp=pkt_time,
            syn=syn, fin=fin, rst=rst, ack=ack, psh=psh, urg=urg
        )

        terminated = _flow_tracker.process_packet(parsed)
        if terminated is not None:
            with _export_queue_lock:
                _export_queue.append(terminated)

    except Exception:
        pass  # Never crash sniffer thread on malformed packet


# ---------------------------------------------------------------------------
# Flow Exporter Background Thread
# ---------------------------------------------------------------------------

def _exporter_thread(api_url: str):
    """Drains terminated and expired flows and posts telemetry to API server."""
    while True:
        time.sleep(FLOW_WINDOW_SECONDS)
        now = time.monotonic()

        # Check for idle/active timeouts
        timed_out = _flow_tracker.check_timeouts(now)

        to_export: List[StatefulFlow] = []
        with _export_queue_lock:
            to_export.extend(_export_queue)
            _export_queue.clear()
        to_export.extend(timed_out)

        if not to_export:
            continue

        log.info(f"Exporting {len(to_export)} completed flow(s) to {api_url}/api/network/telemetry ...")

        for flow in to_export:
            payload = flow.to_api_payload()
            try:
                r = requests.post(
                    f"{api_url}/api/network/telemetry",
                    json=payload,
                    timeout=5
                )
                if r.status_code == 202:
                    result = r.json()
                    log.info(
                        f"Flow INGESTED [UNSCORED - transition guard active]: "
                        f"{flow.initiator_ip}:{flow.initiator_port} -> {flow.responder_ip}:{flow.responder_port} "
                        f"({flow.fwd_packets + flow.bwd_packets} pkts, {flow.duration_ms:.1f}ms) "
                        f"| Pipeline: {result.get('sensorPipeline')}"
                    )
                elif r.status_code == 200:
                    result = r.json()
                    cls = result.get("attackClass", "NORMAL")
                    if cls != "NORMAL":
                        log.warning(
                            f"THREAT DETECTED [{cls}] "
                            f"{flow.initiator_ip}:{flow.initiator_port} -> {flow.responder_ip}:{flow.responder_port} "
                            f"| Score: {result.get('riskScore')} | Reason: {flow.termination_reason}"
                        )
                    else:
                        log.info(
                            f"Flow NORMAL: {flow.initiator_ip}:{flow.initiator_port} -> {flow.responder_ip}:{flow.responder_port} "
                            f"({flow.fwd_packets + flow.bwd_packets} pkts, {flow.fwd_bytes + flow.bwd_bytes} bytes, "
                            f"{flow.duration_ms:.1f}ms, reason={flow.termination_reason})"
                        )
                elif r.status_code == 503:
                    log.debug("Telemetry ingestion paused by server gate (503).")
            except Exception as e:
                log.error(f"Failed to post flow telemetry: {e}")


# ---------------------------------------------------------------------------
# CLI & Entrypoint
# ---------------------------------------------------------------------------

def get_windows_interfaces() -> List[str]:
    """Return available Scapy/Npcap interface names on Windows."""
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        return [i.get("name", "") or i.get("win_index", "") for i in ifaces if i.get("name")]
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description="AI CyberGuard Stateful Network Flow Sensor")
    parser.add_argument("--iface", default=None, help="Network interface name (auto-detect if omitted)")
    parser.add_argument("--api", default="http://127.0.0.1:5000", help="AI CyberGuard API base URL")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument(
        "--pipeline-mode",
        choices=["stateful_v2", "legacy_v1"],
        default="stateful_v2",
        help="Telemetry feature pipeline (default: stateful_v2)"
    )
    args = parser.parse_args()

    try:
        import scapy.all as scapy
    except ImportError:
        log.error("Scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    if args.list_ifaces:
        ifaces = get_windows_interfaces()
        print("Available interfaces:")
        for i in ifaces:
            print(f"  {i}")
        sys.exit(0)

    try:
        r = requests.get(f"{args.api}/api/network/sensor/status", timeout=3)
        if r.status_code == 200:
            status = r.json()
            log.info(f"API Server reachable. Sensor status: {status.get('enabled')}")
    except Exception as e:
        log.warning(f"Could not reach API server at {args.api}: {e}")

    exporter = threading.Thread(target=_exporter_thread, args=(args.api,), daemon=True)
    exporter.start()
    log.info(f"Flow exporter thread started (polling interval: {FLOW_WINDOW_SECONDS}s)")
    log.info(f"Active feature pipeline mode: {args.pipeline_mode}")
    log.warning("TRANSITIONAL NOTICE: Ingested telemetry reaches the active API server, which evaluates against legacy synthetic model v1.")
    log.warning("Do NOT treat legacy model alerts on stateful_v2 telemetry as validated real-world network IDS detections.")

    iface = args.iface
    log.info(f"Starting stateful packet capture (interface: {iface or 'auto-detect'})...")
    log.info("Press Ctrl+C to stop.\n")

    try:
        sniff_kwargs = {"prn": _on_packet, "store": False, "filter": "ip"}
        if iface:
            sniff_kwargs["iface"] = iface
        scapy.sniff(**sniff_kwargs)
    except PermissionError:
        log.error("Administrator privileges required for packet capture.")
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Sensor stopped.")


if __name__ == "__main__":
    main()
