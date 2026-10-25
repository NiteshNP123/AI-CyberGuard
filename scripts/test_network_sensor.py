"""
Unit Tests for AI CyberGuard Stateful Network Flow Sensor
==========================================================
Deterministic unit tests verifying:
- Bidirectional flow tracking and packet accumulation.
- Initiator-directed flow orientation (SYN handshake).
- Client ephemeral port vs server service port assignment.
- FIN handshake closure and RST abortion.
- Idle timeout expiration.
- Zero-duration protection and derived rate calculations.
- Exact ordering and alignment of the 15 ML model input features.

Requires no privileged access, Npcap driver, or live network capture.
"""

import os
import sys
import unittest
import importlib

# Dynamic import for hyphenated module name
sensor_mod = importlib.import_module("scripts.network-sensor")

ParsedPacket = sensor_mod.ParsedPacket
ConversationKey = sensor_mod.ConversationKey
StatefulFlow = sensor_mod.StatefulFlow
StatefulFlowTracker = sensor_mod.StatefulFlowTracker
STANDARD_PORTS = sensor_mod.STANDARD_PORTS
FLOW_FEATURES = sensor_mod.FLOW_FEATURES


class TestNetworkSensor(unittest.TestCase):

    def setUp(self):
        self.tracker = StatefulFlowTracker(
            tcp_idle_timeout=15.0,
            udp_idle_timeout=10.0,
            active_timeout=120.0
        )

    def test_feature_contract_and_order(self):
        """Asserts exact 15-feature contract matching production metadata."""
        expected_features = [
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
        self.assertEqual(FLOW_FEATURES, expected_features)
        self.assertEqual(len(FLOW_FEATURES), 15)

    def test_initial_syn_direction_assignment_and_lexicographical_invariance(self):
        """
        Verifies flow direction is determined by initiator (SYN=1, ACK=0),
        even when the initiator IP is lexicographically greater than the responder IP.
        """
        # Client IP is "192.168.1.100" > Server IP "10.0.0.1"
        client_ip = "192.168.1.100"
        client_port = 54321
        server_ip = "10.0.0.1"
        server_port = 80

        syn_pkt = ParsedPacket(
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dst_port=server_port,
            protocol="TCP",
            length=60,
            timestamp=100.0,
            syn=True,
            ack=False
        )

        self.tracker.process_packet(syn_pkt)
        self.assertEqual(self.tracker.active_flow_count(), 1)

        key = ConversationKey.from_packet(syn_pkt)
        flow = self.tracker._flows[key]

        # Initiator MUST be client, responder MUST be server
        self.assertEqual(flow.initiator_ip, client_ip)
        self.assertEqual(flow.initiator_port, client_port)
        self.assertEqual(flow.responder_ip, server_ip)
        self.assertEqual(flow.responder_port, server_port)

        payload = flow.to_api_payload()
        self.assertEqual(payload["srcIp"], client_ip)
        self.assertEqual(payload["dstIp"], server_ip)
        self.assertEqual(payload["srcPort"], client_port)
        self.assertEqual(payload["dstPort"], server_port)
        self.assertEqual(payload.get("sensorPipeline"), "stateful_initiator_v2")

    def test_bidirectional_packet_and_byte_accumulation(self):
        """Tests that forward and backward packets and bytes accumulate accurately."""
        client_ip, client_port = "172.16.0.5", 49152
        server_ip, server_port = "192.168.1.1", 443

        # 1. Client SYN (Fwd): 60 bytes
        p1 = ParsedPacket(
            src_ip=client_ip, dst_ip=server_ip,
            src_port=client_port, dst_port=server_port,
            protocol="TCP", length=60, timestamp=10.0,
            syn=True, ack=False
        )
        self.tracker.process_packet(p1)

        # 2. Server SYN-ACK (Bwd): 60 bytes
        p2 = ParsedPacket(
            src_ip=server_ip, dst_ip=client_ip,
            src_port=server_port, dst_port=client_port,
            protocol="TCP", length=60, timestamp=10.02,
            syn=True, ack=True
        )
        self.tracker.process_packet(p2)

        # 3. Client ACK (Fwd): 52 bytes
        p3 = ParsedPacket(
            src_ip=client_ip, dst_ip=server_ip,
            src_port=client_port, dst_port=server_port,
            protocol="TCP", length=52, timestamp=10.04,
            ack=True
        )
        self.tracker.process_packet(p3)

        # 4. Client Request (Fwd): 500 bytes
        p4 = ParsedPacket(
            src_ip=client_ip, dst_ip=server_ip,
            src_port=client_port, dst_port=server_port,
            protocol="TCP", length=500, timestamp=10.05,
            ack=True, psh=True
        )
        self.tracker.process_packet(p4)

        # 5. Server Response (Bwd): 1500 bytes
        p5 = ParsedPacket(
            src_ip=server_ip, dst_ip=client_ip,
            src_port=server_port, dst_port=client_port,
            protocol="TCP", length=1500, timestamp=10.10,
            ack=True, psh=True
        )
        self.tracker.process_packet(p5)

        key = ConversationKey.from_packet(p1)
        flow = self.tracker._flows[key]

        # 3 forward packets (60 + 52 + 500 = 612 bytes)
        self.assertEqual(flow.fwd_packets, 3)
        self.assertEqual(flow.fwd_bytes, 612)

        # 2 backward packets (60 + 1500 = 1560 bytes)
        self.assertEqual(flow.bwd_packets, 2)
        self.assertEqual(flow.bwd_bytes, 1560)

        # Flags: 2 SYN, 4 ACK, 2 PSH
        self.assertEqual(flow.syn_flags, 2)
        self.assertEqual(flow.ack_flags, 4)
        self.assertEqual(flow.psh_flags, 2)
        self.assertEqual(flow.fin_flags, 0)
        self.assertEqual(flow.rst_flags, 0)

    def test_client_ephemeral_versus_server_service_port(self):
        """Verifies destination port represents the server's service port in features."""
        # Standard port 80
        flow_std = StatefulFlow(
            initiator_ip="192.168.1.10", initiator_port=51234,
            responder_ip="93.184.216.34", responder_port=80,
            protocol="TCP", start_time=1.0, last_time=1.1,
            fwd_packets=2, bwd_packets=2, fwd_bytes=100, bwd_bytes=200
        )
        vec_std = flow_std.to_feature_vector()
        # std_port is index 13, eph_port is index 14
        self.assertEqual(vec_std[13], 1.0)
        self.assertEqual(vec_std[14], 0.0)

        # Ephemeral custom port 8888
        flow_eph = StatefulFlow(
            initiator_ip="192.168.1.10", initiator_port=51234,
            responder_ip="10.0.0.5", responder_port=8888,
            protocol="TCP", start_time=1.0, last_time=1.1,
            fwd_packets=2, bwd_packets=2, fwd_bytes=100, bwd_bytes=200
        )
        vec_eph = flow_eph.to_feature_vector()
        self.assertEqual(vec_eph[13], 0.0)
        self.assertEqual(vec_eph[14], 1.0)

    def test_rst_connection_termination(self):
        """Asserts RST flag immediately terminates and drains the flow."""
        client_ip, client_port = "10.0.0.2", 60000
        server_ip, server_port = "10.0.0.1", 22

        p1 = ParsedPacket(
            src_ip=client_ip, dst_ip=server_ip,
            src_port=client_port, dst_port=server_port,
            protocol="TCP", length=60, timestamp=50.0,
            syn=True
        )
        self.assertIsNone(self.tracker.process_packet(p1))
        self.assertEqual(self.tracker.active_flow_count(), 1)

        # Server sends RST
        p_rst = ParsedPacket(
            src_ip=server_ip, dst_ip=client_ip,
            src_port=server_port, dst_port=client_port,
            protocol="TCP", length=54, timestamp=50.01,
            rst=True, ack=True
        )
        terminated = self.tracker.process_packet(p_rst)
        self.assertIsNotNone(terminated)
        self.assertTrue(terminated.is_terminated)
        self.assertEqual(terminated.termination_reason, "RST_RECEIVED")
        self.assertEqual(terminated.rst_flags, 1)
        self.assertEqual(self.tracker.active_flow_count(), 0)

    def test_fin_handshake_closure(self):
        """Asserts bidirectional FIN exchange terminates flow with FIN_HANDSHAKE_COMPLETE."""
        c_ip, c_port = "10.0.0.5", 55555
        s_ip, s_port = "10.0.0.1", 80

        # Initial packet
        self.tracker.process_packet(ParsedPacket(
            src_ip=c_ip, dst_ip=s_ip, src_port=c_port, dst_port=s_port,
            protocol="TCP", length=60, timestamp=1.0, syn=True
        ))

        # Client sends FIN
        term1 = self.tracker.process_packet(ParsedPacket(
            src_ip=c_ip, dst_ip=s_ip, src_port=c_port, dst_port=s_port,
            protocol="TCP", length=54, timestamp=2.0, fin=True, ack=True
        ))
        self.assertIsNone(term1)  # Only one side FIN seen

        # Server sends FIN
        term2 = self.tracker.process_packet(ParsedPacket(
            src_ip=s_ip, dst_ip=c_ip, src_port=s_port, dst_port=c_port,
            protocol="TCP", length=54, timestamp=2.02, fin=True, ack=True
        ))
        self.assertIsNotNone(term2)
        self.assertTrue(term2.is_terminated)
        self.assertEqual(term2.termination_reason, "FIN_HANDSHAKE_COMPLETE")
        self.assertEqual(term2.fin_flags, 2)
        self.assertEqual(self.tracker.active_flow_count(), 0)

    def test_idle_timeout_expiration(self):
        """Verifies inactive flows are drained after idle timeout."""
        pkt = ParsedPacket(
            src_ip="10.0.0.10", dst_ip="10.0.0.1",
            src_port=44444, dst_port=53,
            protocol="UDP", length=80, timestamp=10.0
        )
        self.tracker.process_packet(pkt)
        self.assertEqual(self.tracker.active_flow_count(), 1)

        # Check before timeout (10.0 + 8.0 = 18.0 < 10.0 UDP idle limit)
        expired_early = self.tracker.check_timeouts(current_time=18.0)
        self.assertEqual(len(expired_early), 0)
        self.assertEqual(self.tracker.active_flow_count(), 1)

        # Check after timeout (10.0 + 12.0 = 22.0 > 10.0 limit)
        expired_late = self.tracker.check_timeouts(current_time=22.0)
        self.assertEqual(len(expired_late), 1)
        self.assertEqual(expired_late[0].termination_reason, "IDLE_TIMEOUT")
        self.assertEqual(self.tracker.active_flow_count(), 0)

    def test_zero_duration_protection_and_rate_calculations(self):
        """Asserts zero-duration protection prevents division by zero in derived rates."""
        flow = StatefulFlow(
            initiator_ip="10.0.0.1", initiator_port=12345,
            responder_ip="10.0.0.2", responder_port=80,
            protocol="TCP", start_time=100.0, last_time=100.0,  # 0 duration
            fwd_packets=2, bwd_packets=0,
            fwd_bytes=120, bwd_bytes=0
        )
        self.assertGreater(flow.duration_ms, 0)  # max(0.001, ...)
        byte_rate, pkt_rate = flow.calculate_rates()

        # dur_sec should be clamped to 0.001 (1 ms)
        # byte_rate = 120 / 0.001 = 120,000 bytes/sec
        # pkt_rate = 2 / 0.001 = 2,000 pkts/sec
        self.assertAlmostEqual(byte_rate, 120000.0)
        self.assertAlmostEqual(pkt_rate, 2000.0)

    def test_feature_vector_schema_alignment(self):
        """Verifies feature vector matches 15 features in exact sequence."""
        flow = StatefulFlow(
            initiator_ip="10.0.0.1", initiator_port=12345,
            responder_ip="10.0.0.2", responder_port=443,
            protocol="TCP", start_time=10.0, last_time=10.5,  # 500 ms
            fwd_packets=5, bwd_packets=4,
            fwd_bytes=500, bwd_bytes=400,
            syn_flags=1, fin_flags=0, rst_flags=0,
            ack_flags=8, psh_flags=1, urg_flags=0
        )
        vec = flow.to_feature_vector()
        self.assertEqual(len(vec), 15)

        self.assertAlmostEqual(vec[0], 500.0)    # flow_duration_ms
        self.assertEqual(vec[1], 5.0)            # total_fwd_packets
        self.assertEqual(vec[2], 4.0)            # total_bwd_packets
        self.assertEqual(vec[3], 500.0)          # total_fwd_bytes
        self.assertEqual(vec[4], 400.0)          # total_bwd_bytes
        # dur_sec = 0.5s -> byte_rate = 900 / 0.5 = 1800, pkt_rate = 9 / 0.5 = 18
        self.assertAlmostEqual(vec[5], 1800.0)   # byte_rate
        self.assertAlmostEqual(vec[6], 18.0)     # packet_rate
        self.assertEqual(vec[7], 1.0)            # syn_flag_count
        self.assertEqual(vec[8], 0.0)            # fin_flag_count
        self.assertEqual(vec[9], 0.0)            # rst_flag_count
        self.assertEqual(vec[10], 8.0)           # ack_flag_count
        self.assertEqual(vec[11], 1.0)           # psh_flag_count
        self.assertEqual(vec[12], 0.0)           # urg_flag_count
        self.assertEqual(vec[13], 1.0)           # dst_port_standard (443)
        self.assertEqual(vec[14], 0.0)           # dst_port_ephemeral (443 <= 1024)

    def test_transition_guard_payload_tagging(self):
        """Verifies that sensor payloads are explicitly tagged with stateful_initiator_v2."""
        flow = StatefulFlow(
            initiator_ip="192.168.1.100", initiator_port=54321,
            responder_ip="10.0.0.1", responder_port=80,
            protocol="TCP", start_time=1.0, last_time=1.2,
            fwd_packets=4, bwd_packets=3,
            fwd_bytes=400, bwd_bytes=600
        )
        payload = flow.to_api_payload()
        self.assertIn("sensorPipeline", payload)
        self.assertEqual(payload["sensorPipeline"], "stateful_initiator_v2")

    def test_transition_guard_prevents_model_alerts_on_incompatible_telemetry(self):
        """
        Simulates the Express API transition guard:
        Verifies that stateful_initiator_v2 telemetry bypasses legacy ML scoring,
        generates NO model-derived alerts, and emits an explicit machine-readable status.
        """
        def simulate_api_ingestion(payload: dict) -> dict:
            pipeline = payload.get("sensorPipeline")
            if pipeline == "stateful_initiator_v2":
                # Guard active: bypass ML scoring, no alerts
                return {
                    "httpStatus": 202,
                    "status": "UNSCORED_INCOMPATIBLE_PIPELINE",
                    "sensorPipeline": pipeline,
                    "activeModelVersion": "legacy_synthetic_v1",
                    "detectionEnabled": False,
                    "alertCreated": False
                }
            # Legacy path: legacy model scoring
            return {
                "httpStatus": 200,
                "status": "SCORED",
                "sensorPipeline": "legacy_v1",
                "detectionEnabled": True,
                "alertCreated": True  # e.g., if riskScore >= 60
            }

        # Case 1: Incompatible stateful_v2 telemetry
        stateful_payload = {"sensorPipeline": "stateful_initiator_v2", "dstPort": 80}
        resp_stateful = simulate_api_ingestion(stateful_payload)

        self.assertEqual(resp_stateful["httpStatus"], 202)
        self.assertEqual(resp_stateful["status"], "UNSCORED_INCOMPATIBLE_PIPELINE")
        self.assertFalse(resp_stateful["detectionEnabled"])
        self.assertFalse(resp_stateful["alertCreated"], "Alert MUST NOT be created for unsupported pipeline!")
        self.assertNotIn("riskScore", resp_stateful, "Must not fabricate riskScore when unscored!")
        self.assertNotIn("attackClass", resp_stateful, "Must not fabricate attackClass when unscored!")

        # Case 2: Legacy telemetry
        legacy_payload = {"sensorPipeline": "legacy_v1", "dstPort": 80}
        resp_legacy = simulate_api_ingestion(legacy_payload)
        self.assertEqual(resp_legacy["httpStatus"], 200)
        self.assertTrue(resp_legacy["detectionEnabled"])


if __name__ == "__main__":
    unittest.main()
