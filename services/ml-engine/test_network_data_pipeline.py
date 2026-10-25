"""
Unit and Integration Tests for AI CyberGuard Network Data Pipeline
===================================================================
Tests header normalization, label mapping, numerical sanitization,
conflict resolution, group partitioning, temporal guard buffers,
and production model artifact invariance.
"""

import os
import sys
import unittest
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from network_data_pipeline import (
    FLOW_FEATURES,
    CLASSES,
    STANDARD_PORTS,
    normalize_header,
    map_label,
    extract_flow_features,
    resolve_duplicates_and_group,
    partition_dataset
)

class TestNetworkDataPipeline(unittest.TestCase):

    def test_feature_contract_and_ordering(self):
        """Asserts exact 15-feature contract and sequence."""
        expected = [
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
        self.assertEqual(FLOW_FEATURES, expected)
        self.assertEqual(len(FLOW_FEATURES), 15)

    def test_header_normalization(self):
        """Verifies header normalization handles DistriNet corrected variations."""
        raw_headers = [
            "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
            "Timestamp", "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
            "Total Length of Fwd Packet", "Total Length of Bwd Packet",
            "Flow Bytes/s", "Flow Packets/s", "FIN Flag Count", "SYN Flag Count",
            "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
            "Label"
        ]
        normalized, mapping = normalize_header(raw_headers)
        self.assertIn("Dst Port", mapping)
        self.assertIn("Total Fwd Packet", mapping)
        self.assertIn("Total Bwd packets", mapping)
        self.assertIn("Total Length of Fwd Packet", mapping)
        self.assertIn("Total Length of Bwd Packet", mapping)
        self.assertIn("Flow Duration", mapping)
        self.assertIn("Label", mapping)

    def test_missing_required_column_raises(self):
        """Asserts error when a required canonical feature is missing."""
        incomplete_header = ["Flow Duration", "Dst Port", "Label"]
        with self.assertRaises(ValueError) as ctx:
            normalize_header(incomplete_header)
        self.assertIn("Missing required canonical columns", str(ctx.exception))

    def test_label_mapping(self):
        """Tests that all documented labels map to intended classes or explicit exclusions."""
        # Approved classes
        self.assertEqual(map_label("BENIGN"), ("NORMAL", None))
        self.assertEqual(map_label("Benign"), ("NORMAL", None))
        self.assertEqual(map_label("PortScan"), ("PORT_SCAN", None))
        self.assertEqual(map_label("Portscan"), ("PORT_SCAN", None))
        self.assertEqual(map_label("DDoS"), ("DOS_DDOS", None))
        self.assertEqual(map_label("DoS GoldenEye"), ("DOS_DDOS", None))
        self.assertEqual(map_label("DoS slowloris"), ("DOS_DDOS", None))
        self.assertEqual(map_label("DoS Slowhttptest"), ("DOS_DDOS", None))
        self.assertEqual(map_label("FTP-Patator"), ("BRUTE_FORCE", None))
        self.assertEqual(map_label("SSH-Patator"), ("BRUTE_FORCE", None))
        self.assertEqual(map_label("Bot"), ("BOTNET_ANOMALY", None))

        # DoS Hulk controlled ablation
        self.assertEqual(map_label("DoS Hulk", include_dos_hulk=False), (None, "EXCLUDED_DOS_HULK"))
        self.assertEqual(map_label("DoS Hulk", include_dos_hulk=True), ("DOS_DDOS", None))

        # Attempted attacks
        self.assertEqual(map_label("Bot - Attempted"), (None, "EXCLUDED_ATTEMPTED_ATTACK"))
        self.assertEqual(map_label("FTP-Patator - Attempted"), (None, "EXCLUDED_ATTEMPTED_ATTACK"))
        self.assertEqual(map_label("SSH-Patator - Attempted"), (None, "EXCLUDED_ATTEMPTED_ATTACK"))
        self.assertEqual(map_label("DoS Hulk - Attempted"), (None, "EXCLUDED_ATTEMPTED_ATTACK"))
        self.assertEqual(map_label("DoS GoldenEye - Attempted"), (None, "EXCLUDED_ATTEMPTED_ATTACK"))

        # Excluded attacks (never treated as NORMAL)
        self.assertEqual(map_label("Heartbleed"), (None, "EXCLUDED_TINY_SAMPLE_HEARTBLEED"))
        self.assertEqual(map_label("Infiltration"), (None, "EXCLUDED_TINY_SAMPLE_INFILTRATION"))
        self.assertEqual(map_label("Web Attack - Brute Force"), (None, "EXCLUDED_L7_PAYLOAD_REQUIRED"))
        self.assertEqual(map_label("Web Attack - XSS"), (None, "EXCLUDED_L7_PAYLOAD_REQUIRED"))
        self.assertEqual(map_label("Web Attack - Sql Injection"), (None, "EXCLUDED_L7_PAYLOAD_REQUIRED"))

        # Unknown label
        cls, reason = map_label("RandomAttack_123")
        self.assertIsNone(cls)
        self.assertIn("EXCLUDED_UNKNOWN_LABEL", reason)

    def test_bot_campaign_validation_and_exclusion(self):
        """
        Regression tests for DistriNet Ares Botnet campaign criteria:
        - Valid in-window records (03:04:13 PM to 04:02:02 PM CEST targeting 205.174.165.73)
          are mapped to BOTNET_ANOMALY.
        - Out-of-window records (pre-campaign 14:34:13 CEST and post-campaign 16:20:40 CEST)
          are explicitly excluded with reason EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT.
        - Non-Bot classes remain unaffected by contextual fields.
        """
        # Valid in-window Ares C2 bot records
        self.assertEqual(
            map_label("Bot", timestamp="07/07/2017 03:39:36 PM", dst_ip="205.174.165.73", src_ip="192.168.10.5"),
            ("BOTNET_ANOMALY", None)
        )
        # Boundary start (15:04:13 CEST = 13:04:13 UTC)
        self.assertEqual(
            map_label("Bot", timestamp="07/07/2017 03:04:13 PM", dst_ip="205.174.165.73"),
            ("BOTNET_ANOMALY", None)
        )
        # Boundary end (16:02:02 CEST = 14:02:02 UTC)
        self.assertEqual(
            map_label("Bot", timestamp="07/07/2017 04:02:02 PM", dst_ip="205.174.165.73"),
            ("BOTNET_ANOMALY", None)
        )

        # Pre-campaign outlier at 14:34:13 CEST (12:34:13 UTC) to AWS IP
        self.assertEqual(
            map_label("Bot", timestamp="07/07/2017 02:34:13 PM", dst_ip="52.6.13.28", src_ip="192.168.10.12"),
            (None, "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT")
        )

        # Post-campaign outlier at 16:20:40 CEST (14:20:40 UTC) to AWS IP
        self.assertEqual(
            map_label("Bot", timestamp="07/07/2017 04:20:40 PM", dst_ip="52.7.235.158", src_ip="192.168.10.17"),
            (None, "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT")
        )

        # In-window timestamp but non-C2 destination IP
        self.assertEqual(
            map_label("Bot", timestamp="07/07/2017 03:30:00 PM", dst_ip="10.0.0.99"),
            (None, "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT")
        )

        # C2 destination IP but out-of-window timestamp
        self.assertEqual(
            map_label("Bot", timestamp="07/07/2017 01:00:00 PM", dst_ip="205.174.165.73"),
            (None, "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT")
        )

        # Non-Bot records remain completely unaffected
        self.assertEqual(
            map_label("BENIGN", timestamp="07/07/2017 02:34:13 PM", dst_ip="52.6.13.28"),
            ("NORMAL", None)
        )
        self.assertEqual(
            map_label("PortScan", timestamp="07/07/2017 04:20:40 PM", dst_ip="52.7.235.158"),
            ("PORT_SCAN", None)
        )

    def test_numerical_extraction_and_zero_duration(self):
        """Tests unit conversion (us -> ms), zero duration protection, and rate formulas."""
        col_idx = {
            "Flow Duration": 0, "Total Fwd Packet": 1, "Total Bwd packets": 2,
            "Total Length of Fwd Packet": 3, "Total Length of Bwd Packet": 4,
            "Dst Port": 5, "SYN Flag Count": 6, "FIN Flag Count": 7,
            "RST Flag Count": 8, "ACK Flag Count": 9, "PSH Flag Count": 10,
            "URG Flag Count": 11
        }
        # 100,000 us = 100 ms = 0.1 sec
        row = ["100000", "10", "8", "1200", "1800", "80", "1", "1", "0", "17", "2", "0"]
        vec, err = extract_flow_features(row, col_idx)
        self.assertIsNone(err)
        self.assertIsNotNone(vec)
        self.assertEqual(len(vec), 15)

        # Duration in ms
        self.assertAlmostEqual(vec[0], 100.0)
        # Total pkts and bytes
        self.assertEqual(vec[1], 10.0)
        self.assertEqual(vec[2], 8.0)
        self.assertEqual(vec[3], 1200.0)
        self.assertEqual(vec[4], 1800.0)
        # Rates: (1200 + 1800) / 0.1s = 30000 bytes/s; (10 + 8) / 0.1s = 180 pkts/s
        self.assertAlmostEqual(vec[5], 30000.0)
        self.assertAlmostEqual(vec[6], 180.0)
        # Standard port 80 -> std=1, eph=0
        self.assertEqual(vec[13], 1.0)
        self.assertEqual(vec[14], 0.0)

        # Ephemeral port 8088 -> std=0, eph=1
        row_eph = ["100000", "10", "8", "1200", "1800", "8088", "1", "1", "0", "17", "2", "0"]
        vec_eph, _ = extract_flow_features(row_eph, col_idx)
        self.assertEqual(vec_eph[13], 0.0)
        self.assertEqual(vec_eph[14], 1.0)

        # Zero duration handling (dur = 0us) -> dur_sec clamped to 0.001s, no division by zero!
        row_zero = ["0", "2", "0", "120", "0", "443", "1", "0", "0", "0", "0", "0"]
        vec_zero, err_zero = extract_flow_features(row_zero, col_idx)
        self.assertIsNone(err_zero)
        self.assertEqual(vec_zero[0], 0.0)
        self.assertAlmostEqual(vec_zero[5], 120 / 0.001)

        # Negative duration -> rejected deterministically
        row_neg = ["-500", "1", "0", "60", "0", "443", "1", "0", "0", "0", "0", "0"]
        vec_neg, err_neg = extract_flow_features(row_neg, col_idx)
        self.assertIsNone(vec_neg)
        self.assertEqual(err_neg, "INVALID_DURATION_NEGATIVE")

        # NaN input -> rejected deterministically as NaN/Inf
        row_nan = ["NaN", "1", "0", "60", "0", "443", "1", "0", "0", "0", "0", "0"]
        vec_nan, err_nan = extract_flow_features(row_nan, col_idx)
        self.assertIsNone(vec_nan)
        self.assertEqual(err_nan, "NUMERICAL_NAN_OR_INF")

        # Non-numeric input -> rejected deterministically
        row_str = ["invalid_num", "1", "0", "60", "0", "443", "1", "0", "0", "0", "0", "0"]
        vec_str, err_str = extract_flow_features(row_str, col_idx)
        self.assertIsNone(vec_str)
        self.assertEqual(err_str, "INVALID_DURATION_NON_NUMERIC")

    def test_conflicting_label_resolution(self):
        """Tests that identical 15-feature vectors with conflicting labels are purged."""
        mock_records = [
            {"features": [10.0, 1.0, 0.0, 60.0, 0.0, 600.0, 10.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0], "target_class": "NORMAL"},
            {"features": [10.0, 1.0, 0.0, 60.0, 0.0, 600.0, 10.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0], "target_class": "PORT_SCAN"}, # Conflict!
            {"features": [50.0, 5.0, 4.0, 500.0, 600.0, 22000.0, 180.0, 1.0, 1.0, 0.0, 8.0, 1.0, 0.0, 1.0, 0.0], "target_class": "DOS_DDOS"}
        ]
        cleaned, stats = resolve_duplicates_and_group(mock_records)
        # The conflicting pair should be purged
        self.assertEqual(stats["conflicting_label_groups_purged"], 1)
        self.assertEqual(stats["conflicting_label_rows_purged"], 2)
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(cleaned[0]["target_class"], "DOS_DDOS")

    def test_feature_twins_grouped_together(self):
        """Tests that same-label feature twins are grouped and do not cross split partitions."""
        twin_feature = [100.0, 2.0, 2.0, 120.0, 120.0, 2400.0, 40.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 1.0, 0.0]
        mock_records = [
            {"features": twin_feature, "target_class": "NORMAL", "timestamp_raw": "07/07/2017 01:00:00 PM"},
            {"features": twin_feature, "target_class": "NORMAL", "timestamp_raw": "07/07/2017 01:00:05 PM"},
            {"features": twin_feature, "target_class": "NORMAL", "timestamp_raw": "07/07/2017 01:00:10 PM"}
        ]
        cleaned, stats = resolve_duplicates_and_group(mock_records)
        self.assertEqual(stats["same_label_twin_groups"], 1)
        self.assertEqual(stats["same_label_twin_duplicate_rows"], 2)
        # All 3 have identical feature_group_id
        g_ids = {r["feature_group_id"] for r in cleaned}
        self.assertEqual(len(g_ids), 1)

        # When partitioned, all 3 must land in the same split
        train_recs, val_recs, test_recs, _ = partition_dataset(cleaned, random_state=42)
        split_locations = [
            ("train" if cleaned[i] in train_recs else "val" if cleaned[i] in val_recs else "test")
            for i in range(len(cleaned))
        ]
        # All records in the group share the exact same partition
        self.assertEqual(len(set(split_locations)), 1)

    def test_temporal_guard_buffer(self):
        """Tests that single-window traffic drops boundary records inside the 60-second guard buffer."""
        bot_recs = []
        # Create 10 flows over a 1000-second window
        base_time = datetime(2017, 7, 7, 10, 0, 0)
        for i in range(20):
            t = base_time.strftime("%d/%m/%Y %I:%M:%S %p")
            bot_recs.append({
                "features": [50.0 + i, 3.0, 2.0, 100.0, 80.0, 3600.0, 100.0, 1.0, 1.0, 0.0, 4.0, 0.0, 0.0, 0.0, 1.0],
                "target_class": "BOTNET_ANOMALY",
                "timestamp_raw": t,
                "feature_group_id": i + 100
            })
            base_time = datetime.fromtimestamp(base_time.timestamp() + 50) # +50s step

        train_recs, val_recs, test_recs, manifest = partition_dataset(bot_recs, random_state=42)
        # At least one record falling in the 60-second transition buffer should be dropped
        dropped_count = manifest["temporal_guard_dropped_records"].get("BOTNET_ANOMALY", 0)
        self.assertGreater(dropped_count, 0)
        # Train, val, test splits exist
        self.assertGreater(len(train_recs), 0)
        self.assertGreater(len(val_recs), 0)
        self.assertGreater(len(test_recs), 0)

    def test_production_model_artifacts_invariant(self):
        """Verifies that the original production model artifacts remain 100% untouched."""
        expected_hashes = {
            "network_ids_model.joblib": "E35A77DC99FC941ADE05A551945563BD190BC7B39226CDC0DC7C78E587AE3647",
            "network_scaler.joblib": "42A8D05BA199DB44984CE69512E2128C58A739E0C2197EA2111B40D018774703",
            "network_metadata.json": "5C780B2F25093BDC6C3F08CB5E6E5C3AC035355EE49AA4506C83C4C1A61B0889"
        }
        models_dir = os.path.abspath("services/ml-engine/models")
        for filename, expected_hash in expected_hashes.items():
            path = os.path.join(models_dir, filename)
            self.assertTrue(os.path.isfile(path), f"Missing artifact: {path}")
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest().upper()
            self.assertEqual(h, expected_hash, f"Artifact {filename} was altered! Production integrity violated.")

if __name__ == "__main__":
    unittest.main()
