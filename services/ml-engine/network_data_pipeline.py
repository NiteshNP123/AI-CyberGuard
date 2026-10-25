"""
AI CyberGuard - Network Flow IDS Data Preparation Pipeline
============================================================
Handles extraction, validation, cleaning, deduplication, and leakage-resistant
splitting of the corrected CIC-IDS2017 network flow dataset (WTMC 2021).

Outputs prepared splits in services/ml-engine/data/processed/ with strict separation
between features, metadata, and ground truth classes.
"""

import os
import io
import csv
import json
import zipfile
import hashlib
import collections
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Set

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants & Contracts
# ---------------------------------------------------------------------------

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

CLASSES = ["NORMAL", "PORT_SCAN", "DOS_DDOS", "BRUTE_FORCE", "BOTNET_ANOMALY"]

STANDARD_PORTS = {80, 443, 53, 22, 21, 25, 110, 143, 389, 636, 8080}

# Normalized key mapping from possible header variations in raw CSVs
HEADER_SYNONYMS: Dict[str, str] = {
    "flow id": "Flow ID",
    "src ip": "Src IP",
    "source ip": "Src IP",
    "src port": "Src Port",
    "source port": "Src Port",
    "dst ip": "Dst IP",
    "destination ip": "Dst IP",
    "dst port": "Dst Port",
    "destination port": "Dst Port",
    "protocol": "Protocol",
    "timestamp": "Timestamp",
    "flow duration": "Flow Duration",
    "total fwd packet": "Total Fwd Packet",
    "total fwd packets": "Total Fwd Packet",
    "total bwd packets": "Total Bwd packets",
    "total backward packets": "Total Bwd packets",
    "total length of fwd packet": "Total Length of Fwd Packet",
    "total length of fwd packets": "Total Length of Fwd Packet",
    "total length of bwd packet": "Total Length of Bwd Packet",
    "total length of bwd packets": "Total Length of Bwd Packet",
    "flow bytes/s": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "fin flag count": "FIN Flag Count",
    "syn flag count": "SYN Flag Count",
    "rst flag count": "RST Flag Count",
    "psh flag count": "PSH Flag Count",
    "ack flag count": "ACK Flag Count",
    "urg flag count": "URG Flag Count",
    "label": "Label"
}

REQUIRED_CANONICAL_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Flow Bytes/s",
    "Flow Packets/s",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Dst Port",
    "Label"
]

# ---------------------------------------------------------------------------
# Label Mapping
# ---------------------------------------------------------------------------

def map_label(
    label: str,
    include_dos_hulk: bool = False,
    timestamp: str = "",
    dst_ip: str = "",
    src_ip: str = ""
) -> Tuple[Optional[str], Optional[str]]:
    """
    Maps raw dataset label strings to model classes or marks them with explicit exclusion reasons.
    
    Returns:
        (mapped_class, exclusion_reason)
        If excluded: mapped_class is None and exclusion_reason is populated.
        If mapped: mapped_class is one of CLASSES and exclusion_reason is None.
    """
    clean_lbl = label.strip()

    if clean_lbl.endswith(" - Attempted"):
        return None, "EXCLUDED_ATTEMPTED_ATTACK"

    norm_lower = clean_lbl.lower()

    if norm_lower in ["benign"]:
        return "NORMAL", None

    if norm_lower in ["portscan"]:
        return "PORT_SCAN", None

    if clean_lbl in ["DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "DDoS"]:
        return "DOS_DDOS", None

    if clean_lbl == "DoS Hulk":
        if include_dos_hulk:
            return "DOS_DDOS", None
        else:
            # DistriNet researchers recommend against using DoS Hulk as standard malicious class
            # because the simulated traffic was largely ineffective in practice.
            return None, "EXCLUDED_DOS_HULK"

    if clean_lbl in ["FTP-Patator", "SSH-Patator"]:
        return "BRUTE_FORCE", None

    if clean_lbl == "Bot":
        # ---------------------------------------------------------------------------
        # DistriNet Ares Botnet Campaign Ground Truth & Timezone Documentation:
        # ---------------------------------------------------------------------------
        # Publisher reference: WTMC 2021 (DistriNet / KU Leuven, Belgium)
        # Documented C2 attack window in UTC:
        #   Start UTC: 2017-07-07 13:04:13.990571 UTC
        #   End UTC:   2017-07-07 14:02:02.903736 UTC (Duration: 57m 49s)
        # Documented C2 target:
        #   Destination IP: 205.174.165.73 (Ares C2 server)
        # Documented infected victim hosts:
        #   Source IPs: 192.168.10.5, 192.168.10.8, 192.168.10.9, 192.168.10.14, 192.168.10.15
        #
        # Dataset Timestamp Interpretation (Timezone Conversion Assumption):
        #   The raw CSV strings (e.g. "07/07/2017 03:04:13 PM") are naive local-clock
        #   timestamps generated by the capture infrastructure at KU Leuven, Belgium,
        #   which was operating in Central European Summer Time (CEST = UTC+2) on July 7, 2017.
        #   - 13:04:13 UTC corresponds to 15:04:13 CEST (03:04:13 PM).
        #   - 14:02:02 UTC corresponds to 16:02:02 CEST (04:02:02 PM).
        #   In the Friday CSV, exactly 736 effective Bot flows target 205.174.165.73
        #   with timestamps spanning 03:04:13 PM to 04:02:02 PM CEST.
        #
        # Out-of-Window Unresolved Outliers:
        #   Records carrying the raw label "Bot" that violate the documented criteria
        #   (outside the attack interval or targeting non-C2 endpoints) lack authoritative
        #   attribution in DistriNet/UNB documentation. They are excluded under:
        #   EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT.
        # ---------------------------------------------------------------------------
        if timestamp or dst_ip:
            is_valid_c2_dst = (not dst_ip) or (dst_ip.strip() == "205.174.165.73")
            
            is_in_window = True
            if timestamp:
                try:
                    ts = datetime.strptime(timestamp.strip(), "%d/%m/%Y %I:%M:%S %p")
                    c2_start_cest = datetime(2017, 7, 7, 15, 4, 13)
                    c2_end_cest = datetime(2017, 7, 7, 16, 2, 2)
                    is_in_window = (c2_start_cest <= ts <= c2_end_cest)
                except ValueError:
                    is_in_window = False

            if not is_valid_c2_dst or not is_in_window:
                return None, "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT"

        return "BOTNET_ANOMALY", None

    if clean_lbl == "Heartbleed":
        return None, "EXCLUDED_TINY_SAMPLE_HEARTBLEED"

    if clean_lbl == "Infiltration":
        return None, "EXCLUDED_TINY_SAMPLE_INFILTRATION"

    if clean_lbl.startswith("Web Attack"):
        # Application-layer attacks (Brute Force, XSS, SQLi) require payload inspection;
        # flow-only transport metrics cannot discriminate without high benign false alarms.
        return None, "EXCLUDED_L7_PAYLOAD_REQUIRED"

    return None, f"EXCLUDED_UNKNOWN_LABEL_{clean_lbl}"


# ---------------------------------------------------------------------------
# Header Normalization & Validation
# ---------------------------------------------------------------------------

def normalize_header(header: List[str]) -> Tuple[List[str], Dict[str, int]]:
    """
    Validates and normalizes raw CSV headers to canonical names.
    Returns (normalized_headers, canonical_to_index_mapping).
    Raises ValueError if required canonical columns are missing.
    """
    mapping: Dict[str, int] = {}
    normalized: List[str] = []

    for idx, col in enumerate(header):
        cleaned = col.strip()
        canonical = HEADER_SYNONYMS.get(cleaned.lower(), cleaned)
        normalized.append(canonical)
        mapping[canonical] = idx

    missing = [req for req in REQUIRED_CANONICAL_COLUMNS if req not in mapping]
    if missing:
        raise ValueError(f"Malformed CSV header. Missing required canonical columns: {missing}")

    return normalized, mapping


# ---------------------------------------------------------------------------
# Numerical Extraction & Zero-Duration Protection
# ---------------------------------------------------------------------------

def extract_flow_features(row: List[str], col_idx: Dict[str, int]) -> Tuple[Optional[List[float]], Optional[str]]:
    """
    Extracts the 15 normalized flow features from a raw CSV row.
    Converts duration from microseconds to milliseconds.
    Derives byte/packet rates using the exact formula matching main.py.
    
    Returns:
        (feature_vector, error_reason)
    """
    try:
        raw_dur = float(row[col_idx["Flow Duration"]])
    except (ValueError, IndexError):
        return None, "INVALID_DURATION_NON_NUMERIC"

    if raw_dur < 0:
        return None, "INVALID_DURATION_NEGATIVE"

    # Microseconds to milliseconds
    dur_ms = raw_dur / 1000.0

    try:
        fwd_pkts = float(row[col_idx["Total Fwd Packet"]])
        bwd_pkts = float(row[col_idx["Total Bwd packets"]])
        fwd_bytes = float(row[col_idx["Total Length of Fwd Packet"]])
        bwd_bytes = float(row[col_idx["Total Length of Bwd Packet"]])
        dst_port_raw = float(row[col_idx["Dst Port"]])

        syn = float(row[col_idx["SYN Flag Count"]])
        fin = float(row[col_idx["FIN Flag Count"]])
        rst = float(row[col_idx["RST Flag Count"]])
        ack = float(row[col_idx["ACK Flag Count"]])
        psh = float(row[col_idx["PSH Flag Count"]])
        urg = float(row[col_idx["URG Flag Count"]])
    except (ValueError, IndexError):
        return None, "NUMERICAL_PARSING_ERROR"

    # Check for NaN / Inf in raw inputs
    inputs = [raw_dur, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, dst_port_raw, syn, fin, rst, ack, psh, urg]
    if any(np.isnan(v) or np.isinf(v) for v in inputs):
        return None, "NUMERICAL_NAN_OR_INF"

    # Derived rate calculation with explicit zero-duration protection matching main.py
    dur_sec = max(dur_ms / 1000.0, 0.001)
    byte_rate = (fwd_bytes + bwd_bytes) / dur_sec
    packet_rate = (fwd_pkts + bwd_pkts) / dur_sec

    # Port categorization
    port = int(dst_port_raw)
    std_port = 1.0 if port in STANDARD_PORTS else 0.0
    eph_port = 1.0 if port > 1024 else 0.0

    vector = [
        float(dur_ms),
        float(fwd_pkts),
        float(bwd_pkts),
        float(fwd_bytes),
        float(bwd_bytes),
        float(byte_rate),
        float(packet_rate),
        float(syn),
        float(fin),
        float(rst),
        float(ack),
        float(psh),
        float(urg),
        float(std_port),
        float(eph_port)
    ]

    return vector, None


# ---------------------------------------------------------------------------
# Full Archive Auditing & Extraction
# ---------------------------------------------------------------------------

def audit_and_extract_archive(
    zip_path: str,
    include_dos_hulk: bool = False
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Streams all five CSV files in the ZIP archive, audits raw contents,
    discards invalid rows with explicit reasons, and collects valid records.
    
    Returns:
        (records, audit_report)
    """
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"Staged dataset archive not found: {zip_path}")

    records: List[Dict[str, Any]] = []

    audit: Dict[str, Any] = {
        "dataset_archive": os.path.basename(zip_path),
        "archive_size_bytes": os.path.getsize(zip_path),
        "include_dos_hulk": include_dos_hulk,
        "bot_campaign_criteria": {
            "publisher_reference": "DistriNet / KU Leuven (WTMC 2021)",
            "documented_window_utc": "2017-07-07 13:04:13 to 2017-07-07 14:02:02 UTC",
            "timezone_assumption": "CEST (UTC+2 local wall-clock time in raw CSV)",
            "documented_window_cest": "07/07/2017 03:04:13 PM to 07/07/2017 04:02:02 PM CEST",
            "c2_target_ip": "205.174.165.73",
            "c2_target_port": 8080,
            "exclusion_code": "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT"
        },
        "files_inspected": {},
        "raw_label_counts": collections.Counter(),
        "exclusion_reasons": collections.Counter(),
        "excluded_unresolved_bot_records": [],
        "total_raw_rows": 0,
        "exact_source_duplicates": 0,
        "valid_candidate_records": 0
    }

    with zipfile.ZipFile(zip_path, "r") as zf:
        file_list = sorted([name for name in zf.namelist() if name.endswith(".csv")])
        if not file_list:
            raise ValueError(f"No CSV files found in archive {zip_path}")

        for csv_name in file_list:
            print(f"Auditing file: {csv_name} ...")
            file_stats = {
                "raw_rows": 0,
                "exact_duplicates": 0,
                "labels": collections.Counter(),
                "exclusions": collections.Counter()
            }

            seen_raw_hashes: Set[str] = set()

            with zf.open(csv_name, "r") as raw_f:
                text_f = io.TextIOWrapper(raw_f, encoding="utf-8", errors="replace")
                reader = csv.reader(text_f)

                try:
                    raw_header = next(reader)
                except StopIteration:
                    continue

                _, col_idx = normalize_header(raw_header)
                lbl_idx = col_idx["Label"]

                # Metadata indices if available
                ts_idx = col_idx.get("Timestamp", -1)
                src_ip_idx = col_idx.get("Src IP", -1)
                dst_ip_idx = col_idx.get("Dst IP", -1)
                src_port_idx = col_idx.get("Src Port", -1)
                dst_port_idx = col_idx.get("Dst Port", -1)
                proto_idx = col_idx.get("Protocol", -1)

                for row in reader:
                    if not row or len(row) <= lbl_idx:
                        continue

                    file_stats["raw_rows"] += 1
                    audit["total_raw_rows"] += 1

                    raw_label = row[lbl_idx].strip()
                    file_stats["labels"][raw_label] += 1
                    audit["raw_label_counts"][raw_label] += 1

                    # 1. Exact Source Row Deduplication (Category A)
                    # Hash full raw row text
                    row_hash = hashlib.md5("".join(row).encode("utf-8")).hexdigest()
                    if row_hash in seen_raw_hashes:
                        file_stats["exact_duplicates"] += 1
                        file_stats["exclusions"]["EXACT_SOURCE_DUPLICATE"] += 1
                        audit["exact_source_duplicates"] += 1
                        audit["exclusion_reasons"]["EXACT_SOURCE_DUPLICATE"] += 1
                        continue
                    seen_raw_hashes.add(row_hash)

                    # Capture metadata for session, temporal grouping, and contextual validation
                    timestamp_str = row[ts_idx].strip() if ts_idx >= 0 and len(row) > ts_idx else ""
                    src_ip = row[src_ip_idx].strip() if src_ip_idx >= 0 and len(row) > src_ip_idx else ""
                    dst_ip = row[dst_ip_idx].strip() if dst_ip_idx >= 0 and len(row) > dst_ip_idx else ""
                    src_port = row[src_port_idx].strip() if src_port_idx >= 0 and len(row) > src_port_idx else ""
                    dst_port = row[dst_port_idx].strip() if dst_port_idx >= 0 and len(row) > dst_port_idx else ""
                    protocol = row[proto_idx].strip() if proto_idx >= 0 and len(row) > proto_idx else ""

                    # 2. Label Mapping & Exclusion Check
                    target_class, excl_reason = map_label(
                        raw_label,
                        include_dos_hulk=include_dos_hulk,
                        timestamp=timestamp_str,
                        dst_ip=dst_ip,
                        src_ip=src_ip
                    )
                    if excl_reason is not None:
                        file_stats["exclusions"][excl_reason] += 1
                        audit["exclusion_reasons"][excl_reason] += 1
                        if excl_reason == "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT":
                            audit["excluded_unresolved_bot_records"].append({
                                "file": csv_name,
                                "timestamp_raw": timestamp_str,
                                "dst_port": dst_port,
                                "protocol": protocol,
                                "reason": "EXCLUDED_UNRESOLVED_OUT_OF_WINDOW_BOT"
                            })
                        continue

                    # 3. Feature Extraction & Zero-Duration / Numerical Check
                    feat_vec, feat_err = extract_flow_features(row, col_idx)
                    if feat_err is not None:
                        file_stats["exclusions"][feat_err] += 1
                        audit["exclusion_reasons"][feat_err] += 1
                        continue

                    records.append({
                        "features": feat_vec,
                        "target_class": target_class,
                        "raw_label": raw_label,
                        "file": csv_name,
                        "timestamp_raw": timestamp_str,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol
                    })

            audit["files_inspected"][csv_name] = {
                "raw_rows": file_stats["raw_rows"],
                "exact_duplicates": file_stats["exact_duplicates"],
                "labels": dict(file_stats["labels"]),
                "exclusions": dict(file_stats["exclusions"])
            }

    audit["valid_candidate_records"] = len(records)
    audit["raw_label_counts"] = dict(audit["raw_label_counts"])
    audit["exclusion_reasons"] = dict(audit["exclusion_reasons"])

    return records, audit


# ---------------------------------------------------------------------------
# Duplicate Conflicts & Group-Level Partitioning
# ---------------------------------------------------------------------------

def resolve_duplicates_and_group(
    records: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Identifies conflicting 15-feature labels (Category C) and same-label feature twins (Category B).
    Purges conflicting instances and assigns group IDs to feature twins so they cannot cross splits.
    
    Returns:
        (cleaned_records, conflict_and_group_stats)
    """
    feature_to_records: Dict[Tuple, List[Dict[str, Any]]] = collections.defaultdict(list)

    for rec in records:
        # Tuple of rounded feature values to prevent floating-point representation drift
        feat_key = tuple(round(v, 4) for v in rec["features"])
        feature_to_records[feat_key].append(rec)

    cleaned_records: List[Dict[str, Any]] = []
    conflict_groups = 0
    conflict_rows = 0
    twin_groups = 0
    twin_extra_rows = 0
    unique_feature_vectors = len(feature_to_records)

    class_counts_before = collections.Counter(r["target_class"] for r in records)
    class_counts_after = collections.Counter()

    group_id = 0
    for feat_key, group_records in feature_to_records.items():
        distinct_classes = {r["target_class"] for r in group_records}

        # Category C: Conflicting Labels across identical feature vector
        if len(distinct_classes) > 1:
            conflict_groups += 1
            conflict_rows += len(group_records)
            continue  # Purge entirely

        # Category B: Same-label feature twins
        if len(group_records) > 1:
            twin_groups += 1
            twin_extra_rows += (len(group_records) - 1)

        group_id += 1
        for rec in group_records:
            rec["feature_group_id"] = group_id
            rec["feat_key_hash"] = hashlib.md5(str(feat_key).encode("utf-8")).hexdigest()
            cleaned_records.append(rec)
            class_counts_after[rec["target_class"]] += 1

    stats = {
        "initial_candidate_records": len(records),
        "unique_feature_vectors": unique_feature_vectors,
        "conflicting_label_groups_purged": conflict_groups,
        "conflicting_label_rows_purged": conflict_rows,
        "same_label_twin_groups": twin_groups,
        "same_label_twin_duplicate_rows": twin_extra_rows,
        "surviving_cleaned_records": len(cleaned_records),
        "class_counts_before_conflict_resolution": dict(class_counts_before),
        "class_counts_after_conflict_resolution": dict(class_counts_after)
    }

    return cleaned_records, stats


# ---------------------------------------------------------------------------
# Leakage-Resistant Partitioning & Temporal Buffering
# ---------------------------------------------------------------------------

def partition_dataset(
    records: List[Dict[str, Any]],
    random_state: int = 42,
    subsample_caps: Optional[Dict[str, int]] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Partitions data into train (70%), val (15%), and holdout test (15%).
    Uses temporal block chunking with a 60-second guard buffer for single-window
    classes (BOTNET_ANOMALY, PORT_SCAN) and grouped stratified splitting for multi-window classes.
    Feature twins are guaranteed to never cross split boundaries.
    
    Returns:
        (train_records, val_records, test_records, partition_manifest)
    """
    rng = np.random.RandomState(random_state)

    if subsample_caps is None:
        subsample_caps = {
            "NORMAL": 35000,
            "DOS_DDOS": 20000,
            "PORT_SCAN": 15000
            # BRUTE_FORCE and BOTNET_ANOMALY retain 100% of surviving records
        }

    # Group records by target class
    by_class: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for rec in records:
        by_class[rec["target_class"]].append(rec)

    train_all: List[Dict[str, Any]] = []
    val_all: List[Dict[str, Any]] = []
    test_all: List[Dict[str, Any]] = []

    temporal_guard_dropped: Dict[str, int] = collections.defaultdict(int)

    for cls in CLASSES:
        cls_records = by_class[cls]
        if not cls_records:
            continue

        # Controlled majority subsampling (grouped to keep feature twins together)
        if cls in subsample_caps and len(cls_records) > subsample_caps[cls]:
            target_cap = subsample_caps[cls]
            # Group by feature_group_id
            group_map: Dict[int, List[Dict[str, Any]]] = collections.defaultdict(list)
            for r in cls_records:
                group_map[r["feature_group_id"]].append(r)

            shuffled_groups = list(group_map.keys())
            rng.shuffle(shuffled_groups)

            subsampled: List[Dict[str, Any]] = []
            for g_id in shuffled_groups:
                subsampled.extend(group_map[g_id])
                if len(subsampled) >= target_cap:
                    break
            cls_records = subsampled

        # Partitioning logic
        if cls in ["BOTNET_ANOMALY", "PORT_SCAN"]:
            # Single-window temporal chunking with 60-second guard buffer at GROUP level
            # 1. Group records by feature_group_id so feature twins are never split
            group_records_map: Dict[int, List[Dict[str, Any]]] = collections.defaultdict(list)
            for r in cls_records:
                group_records_map[r["feature_group_id"]].append(r)

            # 2. For each group, find its earliest timestamp
            parsed_groups = []
            for g_id, g_recs in group_records_map.items():
                timestamps = []
                for r in g_recs:
                    try:
                        ts = datetime.strptime(r["timestamp_raw"], "%d/%m/%Y %I:%M:%S %p")
                        timestamps.append(ts)
                    except ValueError:
                        pass
                min_ts = min(timestamps) if timestamps else None
                parsed_groups.append((min_ts, g_id, g_recs))

            has_timestamps = all(ts is not None for ts, _, _ in parsed_groups)
            if has_timestamps:
                parsed_groups.sort(key=lambda x: x[0])
                total_groups = len(parsed_groups)
                t_min = parsed_groups[0][0]
                t_max = parsed_groups[-1][0]
                total_duration = (t_max - t_min).total_seconds()

                if total_duration > 180 and total_groups >= 20:
                    idx_70 = int(total_groups * 0.70)
                    t_split1_end = parsed_groups[idx_70][0]
                    t_split2_start = t_split1_end + timedelta(seconds=60)  # 60s guard buffer 1

                    post_guard1 = [g for g in parsed_groups if g[0] >= t_split2_start]
                    if len(post_guard1) >= 4:
                        idx_mid = len(post_guard1) // 2
                        t_split2_end = post_guard1[idx_mid][0]
                        t_split3_start = t_split2_end + timedelta(seconds=60)  # 60s guard buffer 2

                        cls_train = []
                        cls_val = []
                        cls_test = []

                        for ts, g_id, g_recs in parsed_groups:
                            if ts <= t_split1_end:
                                cls_train.extend(g_recs)
                            elif ts < t_split2_start:
                                temporal_guard_dropped[cls] += len(g_recs)
                            elif ts <= t_split2_end:
                                cls_val.extend(g_recs)
                            elif ts < t_split3_start:
                                temporal_guard_dropped[cls] += len(g_recs)
                            else:
                                cls_test.extend(g_recs)

                        # If test got valid samples, accept the group-partitioned split
                        if cls_test and cls_val and cls_train:
                            train_all.extend(cls_train)
                            val_all.extend(cls_val)
                            test_all.extend(cls_test)
                            continue

        # Default Group-Preserving Stratified Split (Feature Twins cannot cross)
        group_map: Dict[int, List[Dict[str, Any]]] = collections.defaultdict(list)
        for r in cls_records:
            group_map[r["feature_group_id"]].append(r)

        groups = list(group_map.keys())
        rng.shuffle(groups)

        n_groups = len(groups)
        n_train = int(n_groups * 0.70)
        n_val = int(n_groups * 0.15)

        for g in groups[:n_train]:
            train_all.extend(group_map[g])
        for g in groups[n_train:n_train + n_val]:
            val_all.extend(group_map[g])
        for g in groups[n_train + n_val:]:
            test_all.extend(group_map[g])

    # Assign split metadata
    for r in train_all: r["split"] = "train"
    for r in val_all: r["split"] = "val"
    for r in test_all: r["split"] = "test"

    manifest = {
        "random_seed": random_state,
        "subsample_caps": subsample_caps,
        "temporal_guard_dropped_records": dict(temporal_guard_dropped),
        "split_counts": {
            "train": len(train_all),
            "val": len(val_all),
            "test": len(test_all),
            "total": len(train_all) + len(val_all) + len(test_all)
        },
        "per_class_splits": {
            cls: {
                "train": sum(1 for r in train_all if r["target_class"] == cls),
                "val": sum(1 for r in val_all if r["target_class"] == cls),
                "test": sum(1 for r in test_all if r["target_class"] == cls),
                "total": sum(1 for r in (train_all + val_all + test_all) if r["target_class"] == cls)
            }
            for cls in CLASSES
        }
    }

    return train_all, val_all, test_all, manifest


# ---------------------------------------------------------------------------
# Serialization & Production Safeguard
# ---------------------------------------------------------------------------

def serialize_processed_datasets(
    train_recs: List[Dict[str, Any]],
    val_recs: List[Dict[str, Any]],
    test_recs: List[Dict[str, Any]],
    audit_report: Dict[str, Any],
    split_manifest: Dict[str, Any],
    output_dir: str
) -> Dict[str, str]:
    """
    Serializes train, val, and holdout test sets to compressed CSV in output_dir.
    Strips socket identifiers and metadata from feature columns, preserving exact 15-feature contract.
    """
    os.makedirs(output_dir, exist_ok=True)

    def to_clean_df(recs: List[Dict[str, Any]]) -> pd.DataFrame:
        matrix = [r["features"] for r in recs]
        df = pd.DataFrame(matrix, columns=FLOW_FEATURES)
        df["target_class"] = [r["target_class"] for r in recs]
        df["target_code"] = [CLASSES.index(r["target_class"]) for r in recs]
        df["feature_group_id"] = [r["feature_group_id"] for r in recs]
        return df

    train_df = to_clean_df(train_recs)
    val_df = to_clean_df(val_recs)
    test_df = to_clean_df(test_recs)

    train_path = os.path.join(output_dir, "train.csv.gz")
    val_path = os.path.join(output_dir, "val.csv.gz")
    test_path = os.path.join(output_dir, "test.csv.gz")
    audit_path = os.path.join(output_dir, "cleaning_audit_report.json")
    manifest_path = os.path.join(output_dir, "split_manifest.json")

    print(f"Exporting {len(train_df):,} training flows to {train_path} ...")
    train_df.to_csv(train_path, compression="gzip", index=False)

    print(f"Exporting {len(val_df):,} validation flows to {val_path} ...")
    val_df.to_csv(val_path, compression="gzip", index=False)

    print(f"Exporting {len(test_df):,} holdout test flows to {test_path} ...")
    test_df.to_csv(test_path, compression="gzip", index=False)

    with open(audit_path, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(split_manifest, f, indent=2)

    return {
        "train": train_path,
        "val": val_path,
        "test": test_path,
        "audit": audit_path,
        "manifest": manifest_path
    }


def execute_full_pipeline(
    zip_path: str = "services/ml-engine/data/cicids2017/dataset.zip",
    output_dir: str = "services/ml-engine/data/processed",
    include_dos_hulk: bool = False,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Orchestrates the complete audit, extraction, conflict purging, grouping,
    and partitioning pipeline.
    """
    print("=" * 60)
    print("AI CYBERGUARD - NETWORK IDS DATA PREPARATION PIPELINE")
    print("=" * 60)

    # 1. Audit and extract raw archive
    records, audit = audit_and_extract_archive(zip_path, include_dos_hulk=include_dos_hulk)
    print(f"\nExtracted {len(records):,} valid candidate records from {audit['total_raw_rows']:,} raw rows.")

    # 2. Duplicate analysis and label conflict purging
    cleaned_records, conflict_stats = resolve_duplicates_and_group(records)
    print(f"Purged {conflict_stats['conflicting_label_rows_purged']:,} conflicting rows across {conflict_stats['conflicting_label_groups_purged']:,} feature groups.")
    print(f"Surviving cleaned records: {len(cleaned_records):,}")

    audit["conflict_and_group_stats"] = conflict_stats

    # 3. Partitioning & Temporal Guarding
    train_recs, val_recs, test_recs, manifest = partition_dataset(
        cleaned_records,
        random_state=random_state
    )

    print("\nDataset Partitioning Complete:")
    print(f"  Train:   {len(train_recs):,} flows ({manifest['split_counts']['train'] / manifest['split_counts']['total'] * 100:.1f}%)")
    print(f"  Val:     {len(val_recs):,} flows ({manifest['split_counts']['val'] / manifest['split_counts']['total'] * 100:.1f}%)")
    print(f"  Test:    {len(test_recs):,} flows ({manifest['split_counts']['test'] / manifest['split_counts']['total'] * 100:.1f}%)")

    # 4. Serialize to disk
    file_map = serialize_processed_datasets(
        train_recs, val_recs, test_recs, audit, manifest, output_dir
    )

    return {
        "file_map": file_map,
        "audit": audit,
        "manifest": manifest
    }


if __name__ == "__main__":
    execute_full_pipeline()
