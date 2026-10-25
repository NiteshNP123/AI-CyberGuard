"""
AI CyberGuard — Stateful PortScan Detector (Isolated Component)
==============================================================
A lightweight, isolated stateful detector that tracks distinct destination ports
contacted per initiating source within a configurable rolling time window.

Design & Architectural Invariants:
- Multi-flow aggregation: Evaluates connection patterns across time rather than
  individual isolated flow features.
- Strict initiator orientation: Tracks probing behavior from the initiating source
  (client) to responder service ports. Never sorts IP addresses lexicographically.
- Distinct-port cardinality: Evaluates unique destination ports contacted, preventing
  repeated connections to a single service from inflating scan evidence.
- Scan episode state machine: Emits exactly one PORTSCAN_EPISODE_STARTED alert upon
  crossing threshold; subsequently aggregates flows into the active episode and closes
  the episode after a configurable cooldown of inactivity.
- Deterministic event-time semantics: Uses information available at the time of each
  event. Rolling window [t - W, t] is inclusive of both endpoints. Out-of-order events
  arriving past the window horizon are handled safely without rewinding window state.
- Component isolation: Unconnected to production API routes, database models, or live
  detection paths. Intended for offline replay and evaluation.

Reference: services/ml-engine/data/experiments/stateful_portscan_feasibility_report.json
"""

import collections
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

log = logging.getLogger("stateful-portscan-detector")


# ---------------------------------------------------------------------------
# Configuration & Event Data Structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PortScanDetectorConfig:
    """
    Configuration for stateful PortScan detection.
    
    Attributes:
        window_sec: Rolling time window in seconds (default 300s / 5 minutes).
        min_distinct_ports: Number of distinct destination ports required to trigger
            a scan episode (default 50 ports, matching feasibility study).
        cooldown_sec: Period of inactivity (in seconds) before an active episode is
            closed and the detector re-arms for that source (default 300s).
        min_rst_ratio: Minimum ratio of RST/aborted flows required if connection-outcome
            filtering is enabled (default 0.0, disabled).
        track_hosts: Whether to track distinct destination IP addresses (default True).
        track_outcomes: Whether to track TCP RST / failed flow outcomes (default True).
        max_out_of_order_sec: Maximum age in seconds of an out-of-order event relative to
            the latest event time before it is rejected as stale (default equal to window_sec).
    """
    window_sec: float = 300.0
    min_distinct_ports: int = 50
    cooldown_sec: float = 300.0
    min_rst_ratio: float = 0.0
    track_hosts: bool = True
    track_outcomes: bool = True
    max_out_of_order_sec: float = 300.0


@dataclass
class PortScanEpisode:
    """
    Represents an ongoing or completed PortScan incident for a specific initiating source.
    """
    episode_id: str
    initiator_ip: str
    start_time: float
    last_seen_time: float
    flow_count: int = 1
    distinct_ports: Set[int] = field(default_factory=set)
    distinct_hosts: Set[str] = field(default_factory=set)
    status: str = "ACTIVE"  # "ACTIVE" or "CLOSED"
    trigger_distinct_ports: int = 0
    trigger_flows_in_window: int = 0

    @property
    def duration_sec(self) -> float:
        """Total duration of the scan episode in seconds."""
        return max(0.0, self.last_seen_time - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes episode to a dictionary."""
        return {
            "episode_id": self.episode_id,
            "initiator_ip": self.initiator_ip,
            "start_time": self.start_time,
            "last_seen_time": self.last_seen_time,
            "duration_sec": round(self.duration_sec, 3),
            "flow_count": self.flow_count,
            "distinct_ports_count": len(self.distinct_ports),
            "distinct_hosts_count": len(self.distinct_hosts),
            "status": self.status,
            "trigger_distinct_ports": self.trigger_distinct_ports,
            "trigger_flows_in_window": self.trigger_flows_in_window
        }


@dataclass(frozen=True)
class PortScanAlertEvent:
    """
    Structured alert emitted on episode lifecycle state changes.
    """
    event_type: str  # "PORTSCAN_EPISODE_STARTED", "PORTSCAN_EPISODE_CLOSED"
    timestamp: float
    initiator_ip: str
    episode_id: str
    distinct_ports_count: int
    distinct_hosts_count: int
    flow_count: int
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes alert to dictionary."""
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "initiator_ip": self.initiator_ip,
            "episode_id": self.episode_id,
            "distinct_ports_count": self.distinct_ports_count,
            "distinct_hosts_count": self.distinct_hosts_count,
            "flow_count": self.flow_count,
            "details": self.details
        }


@dataclass(frozen=True)
class NormalizedFlowEvent:
    """
    Internal normalized representation of a directional flow event.
    """
    timestamp: float
    initiator_ip: str
    responder_ip: str
    responder_port: int
    is_rst: bool = False
    flow_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-Source State Tracker
# ---------------------------------------------------------------------------

class SourceScanState:
    """
    Maintains sliding window state, port frequency map, and episode status
    for a single initiating source IP.
    """

    def __init__(self, initiator_ip: str, config: PortScanDetectorConfig):
        self.initiator_ip = initiator_ip
        self.config = config
        
        # Chronological deque of (timestamp, responder_ip, responder_port, is_rst, flow_id)
        self.window_events: collections.deque = collections.deque()
        self.port_counts: collections.Counter = collections.Counter()
        self.host_counts: collections.Counter = collections.Counter()
        self.rst_count: int = 0
        
        # High-water mark of event time observed for this source
        self.latest_event_time: float = -1.0
        
        # Active scan episode if threshold was crossed
        self.active_episode: Optional[PortScanEpisode] = None
        
        # Deduplication set for recent flow IDs within window
        self.seen_flow_ids: Set[str] = set()

    def evict_expired(self, current_time: float) -> None:
        """
        Evicts events older than (current_time - window_sec).
        Window boundaries: [current_time - window_sec, current_time] is inclusive.
        """
        cutoff = current_time - self.config.window_sec
        while self.window_events and self.window_events[0].timestamp < cutoff:
            old_evt = self.window_events.popleft()
            self.port_counts[old_evt.responder_port] -= 1
            if self.port_counts[old_evt.responder_port] <= 0:
                del self.port_counts[old_evt.responder_port]
                
            self.host_counts[old_evt.responder_ip] -= 1
            if self.host_counts[old_evt.responder_ip] <= 0:
                del self.host_counts[old_evt.responder_ip]
                
            if old_evt.is_rst:
                self.rst_count -= 1
                
            if old_evt.flow_id:
                self.seen_flow_ids.discard(old_evt.flow_id)

    def is_triggered(self) -> bool:
        """
        Evaluates whether current sliding window satisfies detection thresholds.
        """
        distinct_ports = len(self.port_counts)
        if distinct_ports < self.config.min_distinct_ports:
            return False
            
        if self.config.min_rst_ratio > 0.0:
            total_flows = len(self.window_events)
            if total_flows == 0:
                return False
            ratio = self.rst_count / total_flows
            if ratio < self.config.min_rst_ratio:
                return False
                
        return True


# ---------------------------------------------------------------------------
# Main Stateful PortScan Detector Engine
# ---------------------------------------------------------------------------

class StatefulPortScanDetector:
    """
    Isolated stateful detector aggregating flow telemetry across sliding time windows.
    
    Usage:
        detector = StatefulPortScanDetector(PortScanDetectorConfig(min_distinct_ports=50))
        for flow in flow_stream:
            alert = detector.process_flow(flow)
            if alert:
                handle_alert(alert)
    """

    def __init__(self, config: Optional[PortScanDetectorConfig] = None):
        self.config = config or PortScanDetectorConfig()
        self._sources: Dict[str, SourceScanState] = {}
        self._alerts: List[PortScanAlertEvent] = []
        self._closed_episodes: List[PortScanEpisode] = []

    @property
    def alerts(self) -> List[PortScanAlertEvent]:
        """Returns read-only copy of all alerts emitted during session."""
        return list(self._alerts)

    @property
    def closed_episodes(self) -> List[PortScanEpisode]:
        """Returns read-only copy of all closed episodes."""
        return list(self._closed_episodes)

    def get_source_state(self, initiator_ip: str) -> Optional[SourceScanState]:
        """Returns the internal state for an initiator IP, if any."""
        return self._sources.get(initiator_ip)

    def get_active_episodes(self) -> List[PortScanEpisode]:
        """Returns all currently active scan episodes."""
        active = []
        for state in self._sources.values():
            if state.active_episode and state.active_episode.status == "ACTIVE":
                active.append(state.active_episode)
        return active

    def reset(self) -> None:
        """Clears all source states, episodes, and alert history."""
        self._sources.clear()
        self._alerts.clear()
        self._closed_episodes.clear()

    # -----------------------------------------------------------------------
    # Flow Ingestion & Normalization
    # -----------------------------------------------------------------------

    @staticmethod
    def normalize_flow(flow: Any) -> Optional[NormalizedFlowEvent]:
        """
        Defensively extracts and normalizes flow data into a NormalizedFlowEvent.
        Supports:
        - StatefulFlow objects from scripts.network-sensor
        - API payload dictionaries (e.g. from /api/network/telemetry)
        - Generic flow dictionaries
        
        Returns None if record is malformed, missing required fields, or has invalid ports.
        """
        if flow is None:
            return None

        # 1. Handle StatefulFlow object
        if hasattr(flow, "initiator_ip") and hasattr(flow, "responder_port"):
            try:
                initiator_ip = str(flow.initiator_ip).strip()
                responder_ip = str(flow.responder_ip).strip()
                port = int(flow.responder_port)
                ts = float(flow.last_time if hasattr(flow, "last_time") else flow.start_time)
                is_rst = bool(getattr(flow, "rst_flags", 0) > 0)
                flow_id = str(getattr(flow, "flow_id", "")) or None
            except (ValueError, TypeError, AttributeError):
                return None
        # 2. Handle dictionary payloads
        elif isinstance(flow, dict):
            try:
                # Key resolution (supports camelCase API format and snake_case)
                initiator_ip = str(
                    flow.get("srcIp") or flow.get("src_ip") or flow.get("initiator_ip") or ""
                ).strip()
                responder_ip = str(
                    flow.get("dstIp") or flow.get("dst_ip") or flow.get("responder_ip") or ""
                ).strip()
                raw_port = flow.get("dstPort") or flow.get("dst_port") or flow.get("responder_port")
                if raw_port is None:
                    return None
                port = int(raw_port)

                # Timestamp resolution
                raw_ts = (
                    flow.get("timestamp") or 
                    flow.get("start_time") or 
                    flow.get("last_time") or 
                    flow.get("time") or 
                    flow.get("flow_start")
                )
                if raw_ts is None:
                    return None
                ts = float(raw_ts)

                # RST flag resolution
                rst_val = flow.get("rstFlags") or flow.get("rst_flags") or flow.get("rst_flag_count") or 0
                is_rst = bool(float(rst_val) > 0)
                
                flow_id = flow.get("flowId") or flow.get("flow_id") or flow.get("id")
                flow_id = str(flow_id).strip() if flow_id else None
            except (ValueError, TypeError):
                return None
        else:
            return None

        # 3. Defensive Field Validation
        if not initiator_ip or not responder_ip:
            return None
        if not (1 <= port <= 65535):
            return None
        if ts < 0.0 or ts != ts:  # NaN check
            return None

        return NormalizedFlowEvent(
            timestamp=ts,
            initiator_ip=initiator_ip,
            responder_ip=responder_ip,
            responder_port=port,
            is_rst=is_rst,
            flow_id=flow_id
        )

    # -----------------------------------------------------------------------
    # Event Processing Engine
    # -----------------------------------------------------------------------

    def process_flow(self, flow: Any, current_time: Optional[float] = None) -> Optional[PortScanAlertEvent]:
        """
        Ingests a flow event, updates the initiator's sliding window state,
        evaluates thresholds, manages episode lifecycles, and returns an alert
        if an episode was started or closed.
        
        Args:
            flow: StatefulFlow object or telemetry dictionary.
            current_time: Optional explicit timestamp override for evaluation time.
                If omitted, uses the flow's event timestamp.
                
        Returns:
            PortScanAlertEvent if threshold crossed (EPISODE_STARTED) or None.
        """
        event = self.normalize_flow(flow)
        if event is None:
            # Safely discard malformed records without affecting detector state
            return None

        now = event.timestamp if current_time is None else current_time
        src = event.initiator_ip

        # Retrieve or initialize state for initiator
        state = self._sources.get(src)
        if state is None:
            state = SourceScanState(src, self.config)
            self._sources[src] = state

        # Check for duplicate flow ID within the current active window
        if event.flow_id and event.flow_id in state.seen_flow_ids:
            # Duplicate flow: ignore to prevent artificial inflation
            return None

        # Check for out-of-order arrival
        if state.latest_event_time >= 0.0:
            if event.timestamp < (state.latest_event_time - self.config.max_out_of_order_sec):
                # Stale out-of-order event arriving past the window horizon: discard
                log.debug("Discarding stale event for %s (ts=%s, watermark=%s)", src, event.timestamp, state.latest_event_time)
                return None
            # Update watermark if forward
            if event.timestamp > state.latest_event_time:
                state.latest_event_time = event.timestamp
        else:
            state.latest_event_time = event.timestamp

        # Check for episode cooldown expiration before processing new flow
        closure_alert: Optional[PortScanAlertEvent] = None
        if state.active_episode and state.active_episode.status == "ACTIVE":
            idle_time = event.timestamp - state.active_episode.last_seen_time
            if idle_time > self.config.cooldown_sec:
                # Close previous episode due to silence
                closure_alert = self._close_episode(state, event.timestamp, reason="COOLDOWN_EXPIRED")

        # Evict events older than window cutoff [now - window_sec, now]
        state.evict_expired(now)

        # Append new event into window state
        state.window_events.append(event)
        state.port_counts[event.responder_port] += 1
        state.host_counts[event.responder_ip] += 1
        if event.is_rst:
            state.rst_count += 1
        if event.flow_id:
            state.seen_flow_ids.add(event.flow_id)

        # Evaluate threshold & episode state machine
        if state.is_triggered():
            if state.active_episode is None or state.active_episode.status == "CLOSED":
                # START NEW EPISODE
                episode_id = f"ps_ep_{uuid.uuid4().hex[:12]}"
                first_event_ts = state.window_events[0].timestamp if state.window_events else event.timestamp
                episode = PortScanEpisode(
                    episode_id=episode_id,
                    initiator_ip=src,
                    start_time=first_event_ts,
                    last_seen_time=event.timestamp,
                    flow_count=len(state.window_events),
                    distinct_ports=set(state.port_counts.keys()),
                    distinct_hosts=set(state.host_counts.keys()),
                    status="ACTIVE",
                    trigger_distinct_ports=len(state.port_counts),
                    trigger_flows_in_window=len(state.window_events)
                )
                state.active_episode = episode

                alert = PortScanAlertEvent(
                    event_type="PORTSCAN_EPISODE_STARTED",
                    timestamp=event.timestamp,
                    initiator_ip=src,
                    episode_id=episode_id,
                    distinct_ports_count=len(state.port_counts),
                    distinct_hosts_count=len(state.host_counts),
                    flow_count=len(state.window_events),
                    details={
                        "window_sec": self.config.window_sec,
                        "trigger_ports": list(state.port_counts.keys())[:20],
                        "primary_target": event.responder_ip
                    }
                )
                self._alerts.append(alert)
                return alert
            else:
                # UPDATE ACTIVE EPISODE (No duplicate start alert emitted)
                ep = state.active_episode
                ep.last_seen_time = max(ep.last_seen_time, event.timestamp)
                ep.flow_count += 1
                ep.distinct_ports.add(event.responder_port)
                ep.distinct_hosts.add(event.responder_ip)
        elif state.active_episode and state.active_episode.status == "ACTIVE":
            # Flow observed while episode is already active (even if current window dips)
            ep = state.active_episode
            ep.last_seen_time = max(ep.last_seen_time, event.timestamp)
            ep.flow_count += 1
            ep.distinct_ports.add(event.responder_port)
            ep.distinct_hosts.add(event.responder_ip)

        return closure_alert

    def expire_idle_episodes(self, current_time: float) -> List[PortScanAlertEvent]:
        """
        Scans all active episodes and closes any that have exceeded the cooldown
        period without new flows. Useful in periodic ticks or offline replay sweeps.
        
        Args:
            current_time: Current simulation or clock timestamp.
            
        Returns:
            List of PORTSCAN_EPISODE_CLOSED alert events.
        """
        closed_alerts = []
        for state in self._sources.values():
            if state.active_episode and state.active_episode.status == "ACTIVE":
                if (current_time - state.active_episode.last_seen_time) > self.config.cooldown_sec:
                    alert = self._close_episode(state, current_time, reason="SWEEP_TIMEOUT")
                    if alert:
                        closed_alerts.append(alert)
        return closed_alerts

    def _close_episode(
        self,
        state: SourceScanState,
        close_time: float,
        reason: str = "COOLDOWN_EXPIRED"
    ) -> Optional[PortScanAlertEvent]:
        """Internal helper to finalize and record an episode closure."""
        ep = state.active_episode
        if ep is None or ep.status == "CLOSED":
            return None

        ep.status = "CLOSED"
        self._closed_episodes.append(ep)
        state.active_episode = None  # Re-arms source for future episodes
        
        # Reset window events so old episode flows do not immediately re-trigger
        state.window_events.clear()
        state.port_counts.clear()
        state.host_counts.clear()
        state.rst_count = 0
        state.seen_flow_ids.clear()

        alert = PortScanAlertEvent(
            event_type="PORTSCAN_EPISODE_CLOSED",
            timestamp=close_time,
            initiator_ip=ep.initiator_ip,
            episode_id=ep.episode_id,
            distinct_ports_count=len(ep.distinct_ports),
            distinct_hosts_count=len(ep.distinct_hosts),
            flow_count=ep.flow_count,
            details={
                "duration_sec": round(ep.duration_sec, 3),
                "closure_reason": reason
            }
        )
        self._alerts.append(alert)
        return alert

    def get_source_metrics(self, initiator_ip: str) -> Dict[str, Any]:
        """
        Returns snapshot metrics for a given source IP.
        """
        state = self._sources.get(initiator_ip)
        if not state:
            return {
                "initiator_ip": initiator_ip,
                "is_active_episode": False,
                "distinct_ports_in_window": 0,
                "flows_in_window": 0
            }
        return {
            "initiator_ip": initiator_ip,
            "is_active_episode": bool(state.active_episode and state.active_episode.status == "ACTIVE"),
            "active_episode_id": state.active_episode.episode_id if state.active_episode else None,
            "distinct_ports_in_window": len(state.port_counts),
            "distinct_hosts_in_window": len(state.host_counts),
            "flows_in_window": len(state.window_events),
            "latest_event_time": state.latest_event_time
        }
