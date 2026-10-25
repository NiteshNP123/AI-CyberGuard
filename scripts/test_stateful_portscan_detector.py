"""
Unit Tests for Isolated Stateful PortScan Detector
==================================================
Deterministic unit tests covering all 10 required component aspects:
1. Threshold crossing and exactly one episode-start event.
2. Distinct-port counting versus repeated flows to the same port.
3. Rolling-window expiration and boundary behavior.
4. Independent state for multiple sources.
5. Correct initiator/destination orientation.
6. Duplicate records and malformed or missing fields.
7. Late-arriving events and deterministic event-time handling.
8. Episode updates, cooldown, closure, and re-arming.
9. Suppression of repeated alerts while an episode is active.
10. Prevention of future-event information leaking into earlier decisions.

Requires no live network interface, external dependencies, or model artifacts.
"""

import os
import sys
import unittest
from typing import Any, Dict

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.stateful_portscan_detector import (
    PortScanDetectorConfig,
    PortScanEpisode,
    PortScanAlertEvent,
    StatefulPortScanDetector,
    NormalizedFlowEvent
)


class TestStatefulPortScanDetector(unittest.TestCase):

    def setUp(self):
        # Default test config: 10 distinct ports over 60s window, 30s cooldown
        self.config = PortScanDetectorConfig(
            window_sec=60.0,
            min_distinct_ports=10,
            cooldown_sec=30.0,
            min_rst_ratio=0.0,
            track_hosts=True,
            track_outcomes=True,
            max_out_of_order_sec=60.0
        )
        self.detector = StatefulPortScanDetector(self.config)

    # -----------------------------------------------------------------------
    # 1. Threshold crossing and single episode-start event
    # -----------------------------------------------------------------------
    def test_threshold_crossing_emits_exactly_one_start_event(self):
        """Verify that reaching min_distinct_ports triggers exactly one alert."""
        client_ip = "10.0.1.5"
        server_ip = "192.168.1.10"

        # Ports 1 through 9 (under threshold of 10)
        for p in range(1, 10):
            flow = {
                "srcIp": client_ip,
                "dstIp": server_ip,
                "dstPort": p,
                "timestamp": float(p)
            }
            alert = self.detector.process_flow(flow)
            self.assertIsNone(alert, f"Unexpected alert on sub-threshold port {p}")

        self.assertEqual(len(self.detector.alerts), 0)

        # Port 10 hits threshold
        flow_10 = {
            "srcIp": client_ip,
            "dstIp": server_ip,
            "dstPort": 10,
            "timestamp": 10.0
        }
        alert = self.detector.process_flow(flow_10)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "PORTSCAN_EPISODE_STARTED")
        self.assertEqual(alert.initiator_ip, client_ip)
        self.assertEqual(alert.distinct_ports_count, 10)
        self.assertEqual(len(self.detector.alerts), 1)

        # Port 11 (already active)
        flow_11 = {
            "srcIp": client_ip,
            "dstIp": server_ip,
            "dstPort": 11,
            "timestamp": 11.0
        }
        subsequent_alert = self.detector.process_flow(flow_11)
        self.assertIsNone(subsequent_alert, "Expected no duplicate start alert for ongoing episode")
        self.assertEqual(len(self.detector.alerts), 1)

    # -----------------------------------------------------------------------
    # 2. Distinct-port counting vs repeated flows to the same port
    # -----------------------------------------------------------------------
    def test_repeated_flows_to_single_port_never_trigger(self):
        """Assert that high-volume repeated traffic to port 80 does not trigger a scan alert."""
        client_ip = "10.0.1.20"
        server_ip = "10.0.2.1"

        # 500 connections to port 80 (e.g. heavy web browsing)
        for i in range(500):
            flow = {
                "srcIp": client_ip,
                "dstIp": server_ip,
                "dstPort": 80,
                "timestamp": 1.0 + (i * 0.1)  # within 50 seconds (< window_sec 60.0)
            }
            alert = self.detector.process_flow(flow)
            self.assertIsNone(alert)

        metrics = self.detector.get_source_metrics(client_ip)
        self.assertEqual(metrics["distinct_ports_in_window"], 1)
        self.assertEqual(metrics["flows_in_window"], 500)
        self.assertFalse(metrics["is_active_episode"])
        self.assertEqual(len(self.detector.alerts), 0)

    # -----------------------------------------------------------------------
    # 3. Rolling-window expiration and boundary behavior
    # -----------------------------------------------------------------------
    def test_rolling_window_expiration_and_boundaries(self):
        """Verify that events older than [now - window_sec] expire and boundary is inclusive."""
        client_ip = "10.0.1.30"
        server_ip = "10.0.2.2"

        # Window is 60s. Send 5 flows at t = 10.0s on ports 1..5
        for p in range(1, 6):
            self.detector.process_flow({
                "srcIp": client_ip, "dstIp": server_ip, "dstPort": p, "timestamp": 10.0
            })

        metrics = self.detector.get_source_metrics(client_ip)
        self.assertEqual(metrics["distinct_ports_in_window"], 5)

        # Advance to t = 70.0s (delta = 60s). Boundary [70 - 60 = 10.0] is inclusive!
        # Send flow on port 6 at t = 70.0s. The flows at t = 10.0s must STILL be in window.
        self.detector.process_flow({
            "srcIp": client_ip, "dstIp": server_ip, "dstPort": 6, "timestamp": 70.0
        })
        metrics = self.detector.get_source_metrics(client_ip)
        self.assertEqual(metrics["distinct_ports_in_window"], 6)

        # Advance to t = 71.0s (delta = 61s). Cutoff is 71.0 - 60.0 = 11.0s.
        # The 5 flows at t = 10.0s are now strictly expired (< 11.0s) and must be evicted!
        self.detector.process_flow({
            "srcIp": client_ip, "dstIp": server_ip, "dstPort": 7, "timestamp": 71.0
        })
        metrics = self.detector.get_source_metrics(client_ip)
        # Surviving ports: port 6 (t=70) and port 7 (t=71). Ports 1..5 expired.
        self.assertEqual(metrics["distinct_ports_in_window"], 2)

    # -----------------------------------------------------------------------
    # 4. Independent state for multiple sources
    # -----------------------------------------------------------------------
    def test_independent_state_for_multiple_sources(self):
        """Ensure activity from source A does not contribute to source B's thresholds."""
        src_a = "192.168.10.101"
        src_b = "192.168.10.102"
        target = "10.0.0.5"

        # Source A probes 6 distinct ports
        for p in range(1, 7):
            self.detector.process_flow({"srcIp": src_a, "dstIp": target, "dstPort": p, "timestamp": 10.0})

        # Source B probes 6 distinct ports
        for p in range(101, 107):
            self.detector.process_flow({"srcIp": src_b, "dstIp": target, "dstPort": p, "timestamp": 10.0})

        # Neither should trigger (threshold is 10)
        self.assertEqual(len(self.detector.alerts), 0)
        self.assertEqual(self.detector.get_source_metrics(src_a)["distinct_ports_in_window"], 6)
        self.assertEqual(self.detector.get_source_metrics(src_b)["distinct_ports_in_window"], 6)

        # Source A probes 4 more ports (reaching 10)
        for p in range(7, 11):
            alert = self.detector.process_flow({"srcIp": src_a, "dstIp": target, "dstPort": p, "timestamp": 12.0})

        self.assertIsNotNone(alert)
        self.assertEqual(alert.initiator_ip, src_a)
        self.assertEqual(len(self.detector.alerts), 1)

        # Source B remains unalerted
        self.assertFalse(self.detector.get_source_metrics(src_b)["is_active_episode"])

    # -----------------------------------------------------------------------
    # 5. Correct initiator/destination orientation
    # -----------------------------------------------------------------------
    def test_initiator_orientation_independent_of_ip_lexicography(self):
        """Assert that initiator is tracked from connection direction, not IP string sorting."""
        # Case 1: initiator IP is lexicographically greater than responder IP
        # "192.168.1.50" > "10.0.0.1"
        high_ip = "192.168.1.50"
        low_ip = "10.0.0.1"

        class DummyStatefulFlow:
            def __init__(self, init_ip, init_port, resp_ip, resp_port, ts):
                self.initiator_ip = init_ip
                self.initiator_port = init_port
                self.responder_ip = resp_ip
                self.responder_port = resp_port
                self.last_time = ts
                self.rst_flags = 0

        # High IP initiates connection to Low IP service ports
        for p in range(1, 11):
            flow_obj = DummyStatefulFlow(high_ip, 50000 + p, low_ip, p, float(p))
            alert = self.detector.process_flow(flow_obj)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.initiator_ip, high_ip)
        self.assertEqual(alert.distinct_ports_count, 10)

        # Case 2: Low IP is responder; Low IP should NOT have any scan state
        low_metrics = self.detector.get_source_metrics(low_ip)
        self.assertEqual(low_metrics["distinct_ports_in_window"], 0)
        self.assertFalse(low_metrics["is_active_episode"])

    # -----------------------------------------------------------------------
    # 6. Duplicate records and malformed or missing fields
    # -----------------------------------------------------------------------
    def test_malformed_and_duplicate_flow_records(self):
        """Assert defensive validation discards invalid records without throwing errors."""
        # Null flow
        self.assertIsNone(self.detector.process_flow(None))

        # Missing required keys
        self.assertIsNone(self.detector.process_flow({}))
        self.assertIsNone(self.detector.process_flow({"srcIp": "10.0.0.1"}))
        self.assertIsNone(self.detector.process_flow({"srcIp": "10.0.0.1", "dstIp": "10.0.0.2"}))

        # Non-numeric port
        self.assertIsNone(self.detector.process_flow({
            "srcIp": "10.0.0.1", "dstIp": "10.0.0.2", "dstPort": "invalid", "timestamp": 1.0
        }))

        # Port out of bounds (0 or >65535)
        self.assertIsNone(self.detector.process_flow({
            "srcIp": "10.0.0.1", "dstIp": "10.0.0.2", "dstPort": 0, "timestamp": 1.0
        }))
        self.assertIsNone(self.detector.process_flow({
            "srcIp": "10.0.0.1", "dstIp": "10.0.0.2", "dstPort": 70000, "timestamp": 1.0
        }))

        # NaN / negative timestamp
        self.assertIsNone(self.detector.process_flow({
            "srcIp": "10.0.0.1", "dstIp": "10.0.0.2", "dstPort": 80, "timestamp": float("nan")
        }))
        self.assertIsNone(self.detector.process_flow({
            "srcIp": "10.0.0.1", "dstIp": "10.0.0.2", "dstPort": 80, "timestamp": -5.0
        }))

        # Duplicate flow ID test
        flow_a = {
            "flowId": "flow-unique-123",
            "srcIp": "10.0.0.5",
            "dstIp": "10.0.0.6",
            "dstPort": 443,
            "timestamp": 10.0
        }
        self.assertIsNone(self.detector.process_flow(flow_a))
        # Feeding the exact duplicate ID again must be ignored
        self.assertIsNone(self.detector.process_flow(flow_a))
        metrics = self.detector.get_source_metrics("10.0.0.5")
        self.assertEqual(metrics["flows_in_window"], 1)

    # -----------------------------------------------------------------------
    # 7. Late-arriving events and deterministic event-time handling
    # -----------------------------------------------------------------------
    def test_late_arriving_event_past_window_horizon(self):
        """Assert stale out-of-order events do not rewind state watermark."""
        client = "10.10.10.10"
        target = "10.10.10.20"

        # Watermark advances to t = 500.0s
        self.detector.process_flow({"srcIp": client, "dstIp": target, "dstPort": 80, "timestamp": 500.0})
        self.assertEqual(self.detector.get_source_metrics(client)["latest_event_time"], 500.0)

        # Event arrives with timestamp t = 100.0s (age = 400s > max_out_of_order_sec 60s)
        stale_flow = {"srcIp": client, "dstIp": target, "dstPort": 22, "timestamp": 100.0}
        self.assertIsNone(self.detector.process_flow(stale_flow))

        # Watermark remains at 500.0s
        self.assertEqual(self.detector.get_source_metrics(client)["latest_event_time"], 500.0)

    # -----------------------------------------------------------------------
    # 8. Episode updates, cooldown, closure, and re-arming
    # -----------------------------------------------------------------------
    def test_episode_cooldown_closure_and_rearming(self):
        """Verify episode closes after cooldown silence and permits clean re-arming."""
        client = "172.16.5.5"
        target = "10.0.0.1"

        # Trigger Episode 1 at t = 10.0s (10 distinct ports)
        for p in range(1, 11):
            self.detector.process_flow({"srcIp": client, "dstIp": target, "dstPort": p, "timestamp": 10.0})

        self.assertEqual(len(self.detector.alerts), 1)
        ep1 = self.detector.get_source_state(client).active_episode
        self.assertIsNotNone(ep1)
        self.assertEqual(ep1.status, "ACTIVE")
        ep1_id = ep1.episode_id

        # Update Episode 1 at t = 20.0s (within cooldown)
        self.detector.process_flow({"srcIp": client, "dstIp": target, "dstPort": 11, "timestamp": 20.0})
        self.assertEqual(ep1.flow_count, 11)
        self.assertEqual(ep1.last_seen_time, 20.0)

        # Silence for 40s (cooldown is 30s). Event arrives at t = 65.0s (idle = 45s > 30s)
        # This event must close Episode 1 due to cooldown expiration
        close_alert = self.detector.process_flow({
            "srcIp": client, "dstIp": target, "dstPort": 12, "timestamp": 65.0
        })
        self.assertIsNotNone(close_alert)
        self.assertEqual(close_alert.event_type, "PORTSCAN_EPISODE_CLOSED")
        self.assertEqual(close_alert.episode_id, ep1_id)

        # Verify Episode 1 is now recorded in closed_episodes
        self.assertEqual(len(self.detector.closed_episodes), 1)
        self.assertEqual(self.detector.closed_episodes[0].status, "CLOSED")

        # Now source is re-armed! Send 9 more ports at t = 70.0s (reaching 10 distinct in new window)
        for p in range(13, 22):
            alert = self.detector.process_flow({"srcIp": client, "dstIp": target, "dstPort": p, "timestamp": 70.0})

        # New Episode 2 must be triggered!
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "PORTSCAN_EPISODE_STARTED")
        self.assertNotEqual(alert.episode_id, ep1_id)
        self.assertEqual(len(self.detector.alerts), 3)  # [STARTED_1, CLOSED_1, STARTED_2]

    # -----------------------------------------------------------------------
    # 9. Suppression of repeated alerts while episode is active
    # -----------------------------------------------------------------------
    def test_suppression_of_repeated_alerts_during_continuous_scan(self):
        """Assert that 100 continuous probing flows produce only 1 alert during an episode."""
        client = "172.16.100.1"
        target = "192.168.10.50"

        # Cross threshold on first 10 ports
        for p in range(1, 11):
            self.detector.process_flow({"srcIp": client, "dstIp": target, "dstPort": p, "timestamp": 5.0})

        self.assertEqual(len(self.detector.alerts), 1)

        # Continue scanning 100 more ports at 1-second intervals (no idle gap)
        for p in range(11, 111):
            alert = self.detector.process_flow({
                "srcIp": client, "dstIp": target, "dstPort": p, "timestamp": 5.0 + (p - 10)
            })
            self.assertIsNone(alert, f"Unexpected alert on continuous flow {p}")

        # Total alerts must strictly remain 1
        self.assertEqual(len(self.detector.alerts), 1)
        ep = self.detector.get_source_state(client).active_episode
        self.assertEqual(ep.flow_count, 110)
        self.assertEqual(len(ep.distinct_ports), 110)

    # -----------------------------------------------------------------------
    # 10. Prevention of future-event information leakage
    # -----------------------------------------------------------------------
    def test_no_future_information_leakage(self):
        """Verify decision at t=10 depends strictly on information up to t=10."""
        client = "10.50.0.1"
        target = "10.50.0.2"

        # At t=10, client contacts 5 ports (below threshold of 10)
        for p in range(1, 6):
            alert = self.detector.process_flow({
                "srcIp": client, "dstIp": target, "dstPort": p, "timestamp": 10.0
            })
            self.assertIsNone(alert)

        state_at_10 = self.detector.get_source_metrics(client)
        self.assertEqual(state_at_10["distinct_ports_in_window"], 5)
        self.assertFalse(state_at_10["is_active_episode"])

        # Even if 100 ports are contacted at future time t=50, the decision at t=10 was unchanged
        for p in range(6, 16):
            self.detector.process_flow({
                "srcIp": client, "dstIp": target, "dstPort": p, "timestamp": 50.0
            })

        self.assertTrue(self.detector.get_source_metrics(client)["is_active_episode"])


if __name__ == "__main__":
    unittest.main()
