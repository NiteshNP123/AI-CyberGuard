"""
AI CyberGuard — Windows Network Flow Sensor
============================================
Captures real TCP/UDP packets on the authorized local interface using Scapy
(which requires Npcap on Windows). Aggregates packets into 10-second flow
windows, computes the same feature vector expected by the Network IDS ML model,
then POSTs each flow to the existing /api/network/telemetry ingestion endpoint.

Requirements:
  pip install scapy requests
  Npcap must be installed: https://npcap.com/#download (install with WinPcap compat)

Usage:
  python scripts/network-sensor.py [--iface <interface>] [--api http://127.0.0.1:5000]

The sensor ONLY captures traffic on the local authorized interface. It does not
perform deep-packet inspection or capture payload content — only packet-level
metadata (IP, port, TCP flags, byte/packet counts) is used for flow feature
extraction. No payload is transmitted to or stored by the API.
"""

import argparse
import collections
import json
import logging
import os
import socket
import sys
import time
import threading
import traceback
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENSOR] %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("network-sensor")

# ---------------------------------------------------------------------------
# Flow key and accumulator
# ---------------------------------------------------------------------------

@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        return isinstance(other, FlowKey) and asdict(self) == asdict(other)


@dataclass
class FlowAccumulator:
    start_time: float = field(default_factory=time.monotonic)
    last_time: float = field(default_factory=time.monotonic)
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
    fwd_pkt_lengths: List[int] = field(default_factory=list)
    bwd_pkt_lengths: List[int] = field(default_factory=list)


# Active flows indexed by FlowKey
_flows: Dict[FlowKey, FlowAccumulator] = {}
_flows_lock = threading.Lock()

FLOW_WINDOW_SECONDS = 10  # export flow every N seconds
API_URL = "http://127.0.0.1:5000"


# ---------------------------------------------------------------------------
# Scapy packet callback
# ---------------------------------------------------------------------------

def _on_packet(pkt):
    """Called by Scapy for each captured packet."""
    try:
        from scapy.layers.inet import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        pkt_len = len(pkt)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = tcp.flags
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            src_port = udp.sport
            dst_port = udp.dport
            flags = None
        else:
            proto = "OTHER"
            src_port = 0
            dst_port = 0
            flags = None

        # Build canonical (lower IP first) bidirectional flow key
        if src_ip <= dst_ip:
            key = FlowKey(src_ip, dst_ip, src_port, dst_port, proto)
            is_forward = True
        else:
            key = FlowKey(dst_ip, src_ip, dst_port, src_port, proto)
            is_forward = False

        with _flows_lock:
            if key not in _flows:
                _flows[key] = FlowAccumulator()
            acc = _flows[key]
            acc.last_time = time.monotonic()

            if is_forward:
                acc.fwd_packets += 1
                acc.fwd_bytes += pkt_len
                acc.fwd_pkt_lengths.append(pkt_len)
            else:
                acc.bwd_packets += 1
                acc.bwd_bytes += pkt_len
                acc.bwd_pkt_lengths.append(pkt_len)

            if flags is not None:
                # scapy flags are a FlagValue; check bits
                f = int(flags)
                if f & 0x02: acc.syn_flags += 1
                if f & 0x01: acc.fin_flags += 1
                if f & 0x04: acc.rst_flags += 1
                if f & 0x10: acc.ack_flags += 1
                if f & 0x08: acc.psh_flags += 1
                if f & 0x20: acc.urg_flags += 1

    except Exception:
        pass  # never crash the sniffer thread on a malformed packet


# ---------------------------------------------------------------------------
# Flow export thread
# ---------------------------------------------------------------------------

def _exporter_thread(api_url: str):
    """Periodically drains completed flows and POST them to the API."""
    while True:
        time.sleep(FLOW_WINDOW_SECONDS)
        now = time.monotonic()
        to_export = []

        with _flows_lock:
            done_keys = [
                k for k, v in _flows.items()
                if (now - v.last_time) >= FLOW_WINDOW_SECONDS or (now - v.start_time) >= FLOW_WINDOW_SECONDS * 3
            ]
            for k in done_keys:
                to_export.append((k, _flows.pop(k)))

        if not to_export:
            log.debug("No completed flows to export this window.")
            continue

        log.info(f"Exporting {len(to_export)} completed flow(s) to {api_url}/api/network/telemetry ...")

        for key, acc in to_export:
            duration_ms = max(1, int((acc.last_time - acc.start_time) * 1000))
            payload = {
                "srcIp": key.src_ip,
                "dstIp": key.dst_ip,
                "srcPort": key.src_port,
                "dstPort": key.dst_port,
                "protocol": key.protocol,
                "flowDurationMs": duration_ms,
                "totalFwdPackets": acc.fwd_packets,
                "totalBwdPackets": acc.bwd_packets,
                "totalFwdBytes": acc.fwd_bytes,
                "totalBwdBytes": acc.bwd_bytes,
                "synFlags": acc.syn_flags,
                "finFlags": acc.fin_flags,
                "rstFlags": acc.rst_flags,
                "ackFlags": acc.ack_flags,
                "pshFlags": acc.psh_flags,
                "urgFlags": acc.urg_flags,
            }
            try:
                r = requests.post(
                    f"{api_url}/api/network/telemetry",
                    json=payload,
                    timeout=5
                )
                result = r.json()
                if result.get("attackClass") != "NORMAL":
                    log.warning(
                        f"THREAT DETECTED [{result.get('attackClass')}] "
                        f"{key.src_ip}:{key.src_port} -> {key.dst_ip}:{key.dst_port} "
                        f"| Risk: {result.get('riskScore')} | Severity: {result.get('severity')}"
                    )
                else:
                    log.info(
                        f"Flow NORMAL: {key.src_ip}:{key.src_port} -> {key.dst_ip}:{key.dst_port} "
                        f"({acc.fwd_packets + acc.bwd_packets} pkts, {acc.fwd_bytes + acc.bwd_bytes} bytes, {duration_ms}ms)"
                    )
            except Exception as e:
                log.error(f"Failed to POST flow to API: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def get_windows_interfaces():
    """Return available Scapy/Npcap interface names."""
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        return [i.get("name", "") or i.get("win_index", "") for i in ifaces if i.get("name")]
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description="AI CyberGuard Network Flow Sensor")
    parser.add_argument("--iface", default=None, help="Network interface name (auto-detect if omitted)")
    parser.add_argument("--api", default="http://127.0.0.1:5000", help="AI CyberGuard API base URL")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces and exit")
    args = parser.parse_args()

    # Validate Scapy and Npcap presence
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

    # Verify API is reachable
    try:
        r = requests.get(f"{args.api}/api/healthz", timeout=3)
        health = r.json()
        log.info(f"API Server reachable: {health.get('status')} at {args.api}")
    except Exception as e:
        log.error(f"Cannot reach AI CyberGuard API at {args.api}: {e}")
        log.error("Start the API server first: node artifacts/api-server/dist/index.mjs")
        sys.exit(1)

    # Start the flow exporter background thread
    global API_URL
    API_URL = args.api
    exporter = threading.Thread(target=_exporter_thread, args=(args.api,), daemon=True)
    exporter.start()
    log.info(f"Flow exporter started (window: {FLOW_WINDOW_SECONDS}s)")

    # Start Scapy packet capture
    iface = args.iface
    if iface:
        log.info(f"Starting packet capture on interface: {iface}")
    else:
        log.info("Starting packet capture on default interface (auto-detected by Scapy/Npcap)")
        log.info("Use --list-ifaces to see available interfaces, --iface to specify one")

    log.info("Sensor running. Only packet-level metadata (IP, port, flags, byte counts) is captured.")
    log.info("No payload content is inspected, stored, or transmitted.")
    log.info("Press Ctrl+C to stop.\n")

    try:
        sniff_kwargs = {
            "prn": _on_packet,
            "store": False,
            "filter": "ip",  # Only IP traffic; excludes ARP, etc.
        }
        if iface:
            sniff_kwargs["iface"] = iface

        scapy.sniff(**sniff_kwargs)
    except PermissionError:
        log.error("Permission denied. Run this script as Administrator to capture packets.")
        log.error("Right-click your terminal and select 'Run as Administrator'.")
        sys.exit(1)
    except OSError as e:
        if "Npcap" in str(e) or "WinPcap" in str(e) or "No such device" in str(e):
            log.error("Npcap is not installed or the interface was not found.")
            log.error("Install Npcap from: https://npcap.com/#download")
            log.error("Enable 'WinPcap API-compatible Mode' during installation.")
        else:
            log.error(f"Interface error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Sensor stopped.")


if __name__ == "__main__":
    main()
