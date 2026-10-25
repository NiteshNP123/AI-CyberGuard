"""
AI CyberGuard - Network IDS Model Training, Calibration & Experiment Logging
=============================================================================
Batch 4 implementation for training, calibrating, evaluating, and logging
replacement network IDS models using the prepared CIC-IDS2017 dataset.

Safeguards:
- NEVER overwrites or modifies files in services/ml-engine/models/
- Saves all experiment models, scalers, and logs under services/ml-engine/data/experiments/
- Uses Group-Aware Stratified CV (StratifiedGroupKFold) for calibration
- Keeps holdout test partition quarantined until candidate model & calibration are locked
- Exports structured, append-only experiment CSV logs
"""

import os
import sys
import csv
import json
import time
import hashlib
import platform
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)

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
CLASS_TO_CODE = {cls: idx for idx, cls in enumerate(CLASSES)}
CODE_TO_CLASS = {idx: cls for idx, cls in enumerate(CLASSES)}

EXPERIMENTS_DIR = "services/ml-engine/data/experiments"
PRODUCTION_MODELS_DIR = "services/ml-engine/models"

PRODUCTION_ARTIFACT_NAMES = [
    "network_ids_model.joblib",
    "network_scaler.joblib",
    "network_metadata.json"
]


# ---------------------------------------------------------------------------
# Helper Functions: Hashing & System Metadata
# ---------------------------------------------------------------------------

def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 hex digest of a file in binary mode."""
    if not os.path.isfile(filepath):
        return "FILE_NOT_FOUND"
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().upper()


def get_git_revision() -> str:
    """Retrieves current git commit hash."""
    try:
        rev = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()
        return rev
    except Exception:
        return "UNKNOWN_GIT_REV"


def get_software_versions() -> Dict[str, str]:
    """Captures environment and package versions for full reproducibility."""
    import sklearn
    return {
        "python": platform.python_version(),
        "scikit_learn": sklearn.__version__,
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "joblib": joblib.__version__,
        "os": platform.platform()
    }


def verify_production_invariance(baseline_hashes: Dict[str, str]) -> bool:
    """
    Verifies that all production artifacts in services/ml-engine/models/
    remain exactly invariant against baseline hashes.
    """
    for fname, expected_hash in baseline_hashes.items():
        fpath = os.path.join(PRODUCTION_MODELS_DIR, fname)
        current_hash = compute_file_sha256(fpath)
        if current_hash != expected_hash:
            raise RuntimeError(
                f"PRODUCTION INVARIANCE VIOLATION: {fpath} hash changed! "
                f"Expected: {expected_hash}, Got: {current_hash}"
            )
    return True


# ---------------------------------------------------------------------------
# Metric Evaluation Functions
# ---------------------------------------------------------------------------

def compute_multiclass_brier(y_true_indices: np.ndarray, y_prob: np.ndarray, n_classes: int = 5) -> float:
    """
    Computes multi-class Brier score: (1/N) * sum_i sum_k (p_ik - y_ik)^2.
    """
    n_samples = len(y_true_indices)
    if n_samples == 0:
        return 0.0
    y_true_oh = np.zeros((n_samples, n_classes), dtype=float)
    for i, idx in enumerate(y_true_indices):
        y_true_oh[i, idx] = 1.0
    return float(np.mean(np.sum((y_prob - y_true_oh) ** 2, axis=1)))


def compute_ece(y_true_indices: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    """
    Computes Expected Calibration Error (ECE) with equal-width confidence bins.
    """
    n_samples = len(y_true_indices)
    if n_samples == 0:
        return 0.0

    confidences = np.max(y_prob, axis=1)
    predictions = np.argmax(y_prob, axis=1)
    accuracies = (predictions == y_true_indices).astype(float)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]

        if i == n_bins - 1:
            in_bin = (confidences >= bin_lower) & (confidences <= bin_upper)
        else:
            in_bin = (confidences >= bin_lower) & (confidences < bin_upper)

        bin_count = np.sum(in_bin)
        if bin_count > 0:
            bin_acc = np.mean(accuracies[in_bin])
            bin_conf = np.mean(confidences[in_bin])
            ece += (bin_count / n_samples) * abs(bin_acc - bin_conf)

    return float(ece)


def compute_normal_traffic_fpr(y_true_indices: np.ndarray, y_pred_indices: np.ndarray) -> float:
    """
    Normal-traffic false-positive rate:
    Actual NORMAL records classified as any attack / all actual NORMAL records.
    Normal class code is 0.
    """
    normal_mask = (y_true_indices == 0)
    total_normal = int(np.sum(normal_mask))
    if total_normal == 0:
        return 0.0
    false_alarms = int(np.sum(y_pred_indices[normal_mask] != 0))
    return float(false_alarms / total_normal)


def evaluate_predictions(
    y_true_indices: np.ndarray,
    y_pred_indices: np.ndarray,
    y_prob: np.ndarray
) -> Dict[str, Any]:
    """
    Computes comprehensive evaluation metrics including:
    Accuracy, Balanced Accuracy, Macro/Weighted P/R/F1, Per-Class metrics,
    5x5 Confusion Matrix, Normal-traffic FPR, Multi-class Brier score, and ECE.
    """
    acc = float(accuracy_score(y_true_indices, y_pred_indices))
    bacc = float(balanced_accuracy_score(y_true_indices, y_pred_indices))

    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_true_indices, y_pred_indices, average="macro", zero_division=0
    )
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(
        y_true_indices, y_pred_indices, average="weighted", zero_division=0
    )

    per_class_p, per_class_r, per_class_f1, per_class_supp = precision_recall_fscore_support(
        y_true_indices, y_pred_indices, labels=list(range(len(CLASSES))), zero_division=0
    )

    per_class_dict = {}
    for code, cls_name in enumerate(CLASSES):
        per_class_dict[cls_name] = {
            "class_code": code,
            "precision": float(per_class_p[code]),
            "recall": float(per_class_r[code]),
            "f1_score": float(per_class_f1[code]),
            "support": int(per_class_supp[code])
        }

    conf_mat = confusion_matrix(
        y_true_indices, y_pred_indices, labels=list(range(len(CLASSES)))
    ).tolist()

    normal_fpr = compute_normal_traffic_fpr(y_true_indices, y_pred_indices)
    brier = compute_multiclass_brier(y_true_indices, y_prob, n_classes=len(CLASSES))
    ece = compute_ece(y_true_indices, y_prob, n_bins=10)

    return {
        "sample_count": len(y_true_indices),
        "accuracy": acc,
        "balanced_accuracy": bacc,
        "macro_precision": float(macro_p),
        "macro_recall": float(macro_r),
        "macro_f1": float(macro_f1),
        "weighted_precision": float(weighted_p),
        "weighted_recall": float(weighted_r),
        "weighted_f1": float(weighted_f1),
        "normal_fpr": normal_fpr,
        "brier_score": brier,
        "ece": ece,
        "per_class": per_class_dict,
        "confusion_matrix": conf_mat
    }


# ---------------------------------------------------------------------------
# Structured CSV Experiment Logger
# ---------------------------------------------------------------------------

class ExperimentLogger:
    """
    Appends experiment records to standardized CSV files under base_dir.
    Creates files with headers on first write; appends subsequent runs.
    """

    def __init__(self, base_dir: str = EXPERIMENTS_DIR):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

        self.runs_csv = os.path.join(self.base_dir, "training_runs.csv")
        self.metrics_csv = os.path.join(self.base_dir, "experiment_metrics.csv")
        self.per_class_csv = os.path.join(self.base_dir, "per_class_metrics.csv")
        self.conf_mat_csv = os.path.join(self.base_dir, "confusion_matrix.csv")
        self.holdout_preds_csv = os.path.join(self.base_dir, "holdout_predictions.csv")
        self.cleaning_summary_csv = os.path.join(self.base_dir, "cleaning_summary.csv")
        self.label_counts_csv = os.path.join(self.base_dir, "label_counts.csv")
        self.split_counts_csv = os.path.join(self.base_dir, "split_counts.csv")

    def _append_row(self, filepath: str, header: List[str], row: List[Any]):
        file_exists = os.path.isfile(filepath)
        with open(filepath, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            if not file_exists:
                writer.writerow(header)
            writer.writerow(row)

    def log_training_run(
        self,
        run_id: str,
        start_time_utc: str,
        end_time_utc: str,
        status: str,
        error_message: str,
        git_revision: str,
        dataset_archive_sha256: str,
        split_manifest_sha256: str,
        random_seed: int,
        model_class: str,
        model_parameters: Dict[str, Any],
        software_versions: Dict[str, str],
        run_dir: str,
        artifact_paths: Dict[str, str]
    ):
        header = [
            "run_id", "start_time_utc", "end_time_utc", "status", "error_message",
            "git_revision", "dataset_archive_sha256", "split_manifest_sha256",
            "random_seed", "model_class", "model_parameters", "software_versions",
            "run_dir", "artifact_paths"
        ]
        row = [
            run_id, start_time_utc, end_time_utc, status, error_message,
            git_revision, dataset_archive_sha256, split_manifest_sha256,
            random_seed, model_class, json.dumps(model_parameters),
            json.dumps(software_versions), run_dir, json.dumps(artifact_paths)
        ]
        self._append_row(self.runs_csv, header, row)

    def log_experiment_metrics(
        self,
        run_id: str,
        partition: str,
        metrics: Dict[str, Any],
        train_duration_sec: float,
        inference_duration_sec: float,
        model_artifact_sha256: str,
        scaler_artifact_sha256: str
    ):
        header = [
            "run_id", "partition", "sample_count", "train_duration_sec",
            "inference_duration_sec", "accuracy", "balanced_accuracy",
            "macro_precision", "macro_recall", "macro_f1",
            "weighted_precision", "weighted_recall", "weighted_f1",
            "normal_fpr", "brier_score", "ece",
            "model_artifact_sha256", "scaler_artifact_sha256"
        ]
        row = [
            run_id,
            partition,
            metrics["sample_count"],
            f"{train_duration_sec:.4f}",
            f"{inference_duration_sec:.4f}",
            f"{metrics['accuracy']:.6f}",
            f"{metrics['balanced_accuracy']:.6f}",
            f"{metrics['macro_precision']:.6f}",
            f"{metrics['macro_recall']:.6f}",
            f"{metrics['macro_f1']:.6f}",
            f"{metrics['weighted_precision']:.6f}",
            f"{metrics['weighted_recall']:.6f}",
            f"{metrics['weighted_f1']:.6f}",
            f"{metrics['normal_fpr']:.6f}",
            f"{metrics['brier_score']:.6f}",
            f"{metrics['ece']:.6f}",
            model_artifact_sha256,
            scaler_artifact_sha256
        ]
        self._append_row(self.metrics_csv, header, row)

    def log_per_class_metrics(self, run_id: str, partition: str, per_class: Dict[str, Dict[str, Any]]):
        header = ["run_id", "partition", "class_name", "class_code", "precision", "recall", "f1_score", "support"]
        for cls_name, vals in per_class.items():
            row = [
                run_id,
                partition,
                cls_name,
                vals["class_code"],
                f"{vals['precision']:.6f}",
                f"{vals['recall']:.6f}",
                f"{vals['f1_score']:.6f}",
                vals["support"]
            ]
            self._append_row(self.per_class_csv, header, row)

    def log_confusion_matrix(self, run_id: str, partition: str, matrix: List[List[int]]):
        header = ["run_id", "partition", "actual_class", "predicted_class", "count"]
        for actual_idx, actual_cls in enumerate(CLASSES):
            for pred_idx, pred_cls in enumerate(CLASSES):
                row = [run_id, partition, actual_cls, pred_cls, matrix[actual_idx][pred_idx]]
                self._append_row(self.conf_mat_csv, header, row)

    def log_holdout_predictions(
        self,
        run_id: str,
        actual_indices: np.ndarray,
        pred_indices: np.ndarray,
        probabilities: np.ndarray
    ):
        header = [
            "run_id", "record_id", "actual_class", "predicted_class",
            "prob_NORMAL", "prob_PORT_SCAN", "prob_DOS_DDOS", "prob_BRUTE_FORCE", "prob_BOTNET_ANOMALY"
        ]
        file_exists = os.path.isfile(self.holdout_preds_csv)
        with open(self.holdout_preds_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            if not file_exists:
                writer.writerow(header)
            for idx in range(len(actual_indices)):
                act_cls = CODE_TO_CLASS[actual_indices[idx]]
                pred_cls = CODE_TO_CLASS[pred_indices[idx]]
                probs = probabilities[idx]
                row = [
                    run_id,
                    idx,
                    act_cls,
                    pred_cls,
                    f"{probs[0]:.6f}",
                    f"{probs[1]:.6f}",
                    f"{probs[2]:.6f}",
                    f"{probs[3]:.6f}",
                    f"{probs[4]:.6f}"
                ]
                writer.writerow(row)

    def export_data_summaries(
        self,
        run_id: str,
        audit_report: Dict[str, Any],
        split_manifest: Dict[str, Any]
    ):
        # 1. Cleaning summary
        clean_hdr = [
            "run_id", "dataset_archive", "archive_size_bytes", "total_raw_rows",
            "exact_source_duplicates", "valid_candidate_records",
            "purged_conflict_groups", "purged_conflict_rows", "surviving_cleaned_records"
        ]
        conf_stats = audit_report.get("conflict_and_group_stats", {})
        clean_row = [
            run_id,
            audit_report.get("dataset_archive", "unknown"),
            audit_report.get("archive_size_bytes", 0),
            audit_report.get("total_raw_rows", 0),
            audit_report.get("exact_source_duplicates", 0),
            audit_report.get("valid_candidate_records", 0),
            conf_stats.get("conflicting_label_groups_purged", 0),
            conf_stats.get("conflicting_label_rows_purged", 0),
            conf_stats.get("surviving_cleaned_records", 0)
        ]
        self._append_row(self.cleaning_summary_csv, clean_hdr, clean_row)

        # 2. Label counts (raw, exclusions)
        lbl_hdr = ["run_id", "label_name", "count", "category"]
        for lbl, cnt in audit_report.get("raw_label_counts", {}).items():
            self._append_row(self.label_counts_csv, lbl_hdr, [run_id, lbl, cnt, "raw_source"])
        for excl, cnt in audit_report.get("exclusion_reasons", {}).items():
            self._append_row(self.label_counts_csv, lbl_hdr, [run_id, excl, cnt, "exclusion_reason"])

        # 3. Split counts
        split_hdr = ["run_id", "class_name", "train_count", "val_count", "test_count", "total_count"]
        for cls_name, counts in split_manifest.get("per_class_splits", {}).items():
            row = [
                run_id,
                cls_name,
                counts.get("train", 0),
                counts.get("val", 0),
                counts.get("test", 0),
                counts.get("total", 0)
            ]
            self._append_row(self.split_counts_csv, split_hdr, row)


# ---------------------------------------------------------------------------
# Core Training, Calibration & Evaluation Pipeline
# ---------------------------------------------------------------------------

def run_experiment(
    run_id: str,
    train_path: str,
    val_path: str,
    test_path: str,
    audit_path: str,
    manifest_path: str,
    archive_path: str,
    run_output_dir: str,
    baseline_production_hashes: Dict[str, str],
    random_seed: int = 42,
    n_estimators: int = 150,
    max_depth: int = 16,
    class_weight: str = "balanced"
) -> Dict[str, Any]:
    """
    Executes an end-to-end training and evaluation run with all Batch 4 safeguards.
    """
    start_time_utc = datetime.now(timezone.utc).isoformat()
    logger = ExperimentLogger(EXPERIMENTS_DIR)
    git_rev = get_git_revision()
    sw_versions = get_software_versions()
    archive_sha256 = compute_file_sha256(archive_path)
    manifest_sha256 = compute_file_sha256(manifest_path)

    model_params = {
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "class_weight": class_weight,
        "random_state": random_seed,
        "calibration_cv": "StratifiedGroupKFold(n_splits=5)",
        "calibration_method": "sigmoid"
    }

    artifacts_dir = os.path.join(run_output_dir, "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    print(f"\n{'='*70}")
    print(f"STARTING EXPERIMENT RUN: {run_id}")
    print(f"{'='*70}")

    # Guard 1: Verify production models are unchanged
    verify_production_invariance(baseline_production_hashes)

    try:
        # 1. Load audit report and split manifest
        with open(audit_path, "r", encoding="utf-8") as f:
            audit_report = json.load(f)
        with open(manifest_path, "r", encoding="utf-8") as f:
            split_manifest = json.load(f)

        logger.export_data_summaries(run_id, audit_report, split_manifest)

        # 2. Load Train and Validation data (Test set remains QUARANTINED)
        print(f"Loading training data from {train_path} ...")
        train_df = pd.read_csv(train_path)
        print(f"Loading validation data from {val_path} ...")
        val_df = pd.read_csv(val_path)

        # Feature validation
        missing_feats = [col for col in FLOW_FEATURES if col not in train_df.columns]
        if missing_feats:
            raise ValueError(f"Missing required flow features in training data: {missing_feats}")

        X_train_raw = train_df[FLOW_FEATURES].values
        y_train = train_df["target_code"].values
        groups_train = train_df["feature_group_id"].values

        X_val_raw = val_df[FLOW_FEATURES].values
        y_val = val_df["target_code"].values

        # 3. Fit StandardScaler on Train ONLY; transform Validation
        print("Fitting StandardScaler strictly on training set ...")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train_raw)
        X_val_scaled = scaler.transform(X_val_raw)

        # 4. StratifiedGroupKFold cross-validation folds for calibration
        print("Generating group-aware folds using StratifiedGroupKFold(n_splits=5) ...")
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_seed)
        custom_splits = list(sgkf.split(X_train_scaled, y_train, groups=groups_train))

        # Check fold disjointness
        for fold_idx, (tr_idx, cv_val_idx) in enumerate(custom_splits):
            tr_groups = set(groups_train[tr_idx])
            val_groups = set(groups_train[cv_val_idx])
            overlap = tr_groups.intersection(val_groups)
            if overlap:
                raise RuntimeError(
                    f"Data leakage detected in calibration fold {fold_idx}: "
                    f"{len(overlap)} feature groups cross fold boundary!"
                )

        # 5. Train Base Random Forest
        t0_train = time.time()
        print(f"Training base RandomForestClassifier ({n_estimators} trees, depth {max_depth}) ...")
        base_rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight=class_weight,
            random_state=random_seed,
            n_jobs=-1
        )
        base_rf.fit(X_train_scaled, y_train)

        # 6. Fit CalibratedClassifierCV using custom group folds
        print("Fitting CalibratedClassifierCV (sigmoid) with group-aware folds ...")
        cal_rf = CalibratedClassifierCV(
            estimator=base_rf,
            cv=custom_splits,
            method="sigmoid"
        )
        cal_rf.fit(X_train_scaled, y_train)
        train_duration = time.time() - t0_train
        print(f"Model training and calibration completed in {train_duration:.2f} seconds.")

        # 7. Evaluate on Validation Split (Compare Base RF vs Calibrated RF)
        t0_val = time.time()
        val_pred_cal = cal_rf.predict(X_val_scaled)
        val_prob_cal = cal_rf.predict_proba(X_val_scaled)
        val_duration = time.time() - t0_val

        val_pred_base = base_rf.predict(X_val_scaled)
        val_prob_base = base_rf.predict_proba(X_val_scaled)

        val_metrics_cal = evaluate_predictions(y_val, val_pred_cal, val_prob_cal)
        val_metrics_base = evaluate_predictions(y_val, val_pred_base, val_prob_base)

        print("\n--- VALIDATION EVALUATION RESULTS ---")
        print(f"Base RF:       Acc={val_metrics_base['accuracy']:.4f}, BalAcc={val_metrics_base['balanced_accuracy']:.4f}, MacroF1={val_metrics_base['macro_f1']:.4f}, NormalFPR={val_metrics_base['normal_fpr']:.4f}, Brier={val_metrics_base['brier_score']:.4f}, ECE={val_metrics_base['ece']:.4f}")
        print(f"Calibrated RF: Acc={val_metrics_cal['accuracy']:.4f}, BalAcc={val_metrics_cal['balanced_accuracy']:.4f}, MacroF1={val_metrics_cal['macro_f1']:.4f}, NormalFPR={val_metrics_cal['normal_fpr']:.4f}, Brier={val_metrics_cal['brier_score']:.4f}, ECE={val_metrics_cal['ece']:.4f}")

        # Choose Calibrated RF as locked candidate
        locked_model = cal_rf
        locked_val_metrics = val_metrics_cal

        # 8. Save Candidate Artifacts into Experiment Directory
        cand_model_path = os.path.join(artifacts_dir, "candidate_network_ids_model.joblib")
        cand_scaler_path = os.path.join(artifacts_dir, "candidate_network_scaler.joblib")
        cand_meta_path = os.path.join(artifacts_dir, "candidate_network_metadata.json")

        print(f"Saving candidate artifacts to {artifacts_dir} ...")
        joblib.dump(locked_model, cand_model_path)
        joblib.dump(scaler, cand_scaler_path)

        cand_model_hash = compute_file_sha256(cand_model_path)
        cand_scaler_hash = compute_file_sha256(cand_scaler_path)

        # Log Validation Metrics
        logger.log_experiment_metrics(
            run_id=run_id,
            partition="validation",
            metrics=locked_val_metrics,
            train_duration_sec=train_duration,
            inference_duration_sec=val_duration,
            model_artifact_sha256=cand_model_hash,
            scaler_artifact_sha256=cand_scaler_hash
        )
        logger.log_per_class_metrics(run_id, "validation", locked_val_metrics["per_class"])
        logger.log_confusion_matrix(run_id, "validation", locked_val_metrics["confusion_matrix"])

        # 9. LOCK CANDIDATE & ACCESS HOLDOUT TEST SET
        print("\nCandidate model, scaler, and calibration parameters LOCKED.")
        print(f"Loading QUARANTINED holdout test set from {test_path} ...")
        test_df = pd.read_csv(test_path)
        X_test_raw = test_df[FLOW_FEATURES].values
        y_test = test_df["target_code"].values

        # Transform test set using the fitted scaler
        X_test_scaled = scaler.transform(X_test_raw)

        # 10. Evaluate Locked Candidate on Holdout Test Set
        t0_test = time.time()
        test_pred = locked_model.predict(X_test_scaled)
        test_prob = locked_model.predict_proba(X_test_scaled)
        test_duration = time.time() - t0_test

        test_metrics = evaluate_predictions(y_test, test_pred, test_prob)

        print("\n--- HOLDOUT TEST EVALUATION RESULTS ---")
        print(f"Accuracy:          {test_metrics['accuracy']:.4f}")
        print(f"Balanced Accuracy: {test_metrics['balanced_accuracy']:.4f}")
        print(f"Macro F1:          {test_metrics['macro_f1']:.4f}")
        print(f"Weighted F1:       {test_metrics['weighted_f1']:.4f}")
        print(f"Normal-Traffic FPR:{test_metrics['normal_fpr']:.6f}")
        print(f"Multi-class Brier: {test_metrics['brier_score']:.6f}")
        print(f"ECE (10 bins):     {test_metrics['ece']:.6f}")

        print("\nPer-Class Holdout Metrics:")
        for cls_name, vals in test_metrics["per_class"].items():
            print(f"  {cls_name:15s}: Prec={vals['precision']:.4f}, Rec={vals['recall']:.4f}, F1={vals['f1_score']:.4f}, Support={vals['support']}")

        # 11. Log Test Metrics & Holdout Predictions
        logger.log_experiment_metrics(
            run_id=run_id,
            partition="test",
            metrics=test_metrics,
            train_duration_sec=train_duration,
            inference_duration_sec=test_duration,
            model_artifact_sha256=cand_model_hash,
            scaler_artifact_sha256=cand_scaler_hash
        )
        logger.log_per_class_metrics(run_id, "test", test_metrics["per_class"])
        logger.log_confusion_matrix(run_id, "test", test_metrics["confusion_matrix"])
        logger.log_holdout_predictions(run_id, y_test, test_pred, test_prob)

        # 12. Write Candidate Metadata JSON
        candidate_metadata = {
            "model_type": "RandomForestClassifier (CalibratedClassifierCV, sigmoid)",
            "run_id": run_id,
            "created_at_utc": start_time_utc,
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            "git_revision": git_rev,
            "dataset": "DistriNet Corrected CIC-IDS2017 (WTMC 2021)",
            "dataset_archive_sha256": archive_sha256,
            "split_manifest_sha256": manifest_sha256,
            "features": FLOW_FEATURES,
            "classes": CLASSES,
            "class_to_code": CLASS_TO_CODE,
            "code_to_class": CODE_TO_CLASS,
            "sample_counts": {
                "train": len(train_df),
                "val": len(val_df),
                "test": len(test_df),
                "total": len(train_df) + len(val_df) + len(test_df)
            },
            "hyperparameters": model_params,
            "validation_metrics": locked_val_metrics,
            "holdout_test_metrics": test_metrics,
            "evaluation_notes": [
                "Temporal holdout with 60s guard buffers used for BOTNET_ANOMALY and PORT_SCAN.",
                "BOTNET_ANOMALY test support is N=63 flows; evaluation is within-capture.",
                "Calibrated probabilities evaluated via Expected Calibration Error (ECE) and Brier score.",
                "Normal-traffic false-positive rate rigorously measured against true benign flows."
            ]
        }

        with open(cand_meta_path, "w", encoding="utf-8") as f:
            json.dump(candidate_metadata, f, indent=2)

        artifact_paths = {
            "model": cand_model_path,
            "scaler": cand_scaler_path,
            "metadata": cand_meta_path
        }

        end_time_utc = datetime.now(timezone.utc).isoformat()

        # Log Successful Run
        logger.log_training_run(
            run_id=run_id,
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
            status="SUCCESS",
            error_message="",
            git_revision=git_rev,
            dataset_archive_sha256=archive_sha256,
            split_manifest_sha256=manifest_sha256,
            random_seed=random_seed,
            model_class="CalibratedClassifierCV[RandomForestClassifier]",
            model_parameters=model_params,
            software_versions=sw_versions,
            run_dir=run_output_dir,
            artifact_paths=artifact_paths
        )

        # Guard 2: Verify production models remain unchanged after experiment
        verify_production_invariance(baseline_production_hashes)

        return {
            "status": "SUCCESS",
            "run_id": run_id,
            "validation_metrics": locked_val_metrics,
            "test_metrics": test_metrics,
            "artifact_paths": artifact_paths,
            "artifact_hashes": {
                "model": cand_model_hash,
                "scaler": cand_scaler_hash
            }
        }

    except Exception as e:
        end_time_utc = datetime.now(timezone.utc).isoformat()
        err_msg = str(e)
        print(f"EXPERIMENT RUN FAILED: {err_msg}")
        logger.log_training_run(
            run_id=run_id,
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
            status="FAILURE",
            error_message=err_msg,
            git_revision=git_rev,
            dataset_archive_sha256=archive_sha256,
            split_manifest_sha256=manifest_sha256,
            random_seed=random_seed,
            model_class="CalibratedClassifierCV[RandomForestClassifier]",
            model_parameters=model_params,
            software_versions=sw_versions,
            run_dir=run_output_dir,
            artifact_paths={}
        )
        # Check production invariance even on failure
        verify_production_invariance(baseline_production_hashes)
        raise


# ---------------------------------------------------------------------------
# DoS Hulk Controlled Ablation Runner
# ---------------------------------------------------------------------------

def run_dos_hulk_ablation(
    baseline_production_hashes: Dict[str, str],
    zip_path: str = "services/ml-engine/data/cicids2017/dataset.zip",
    ablation_dir: str = "services/ml-engine/data/experiments/ablation_dos_hulk"
) -> Dict[str, Any]:
    """
    Executes a controlled ablation run that includes DoS Hulk in the DOS_DDOS class.
    Saves data, manifests, and candidate models in isolated subdirectories.
    """
    print(f"\n{'='*70}")
    print("STARTING DOS HULK ABLATION PIPELINE & TRAINING")
    print(f"{'='*70}")

    from network_data_pipeline import execute_full_pipeline

    ablation_data_dir = os.path.join(ablation_dir, "data")
    ablation_run_id = "exp_20261025_cicids2017_ablation_dos_hulk"

    # 1. Run pipeline with include_dos_hulk=True
    print("Generating ablation dataset with DoS Hulk included ...")
    pipe_out = execute_full_pipeline(
        zip_path=zip_path,
        output_dir=ablation_data_dir,
        include_dos_hulk=True,
        random_state=42
    )

    file_map = pipe_out["file_map"]

    # 2. Train and evaluate ablation model
    result = run_experiment(
        run_id=ablation_run_id,
        train_path=file_map["train"],
        val_path=file_map["val"],
        test_path=file_map["test"],
        audit_path=file_map["audit"],
        manifest_path=file_map["manifest"],
        archive_path=zip_path,
        run_output_dir=ablation_dir,
        baseline_production_hashes=baseline_production_hashes,
        random_seed=42
    )

    return result


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def main():
    # 1. Capture production hashes to guarantee invariance
    baseline_hashes = {
        fname: compute_file_sha256(os.path.join(PRODUCTION_MODELS_DIR, fname))
        for fname in PRODUCTION_ARTIFACT_NAMES
    }
    print("Baseline Production Hashes:")
    for fn, h in baseline_hashes.items():
        print(f"  {fn}: {h}")

    # 2. Run Primary Experiment (DoS Hulk Excluded)
    primary_run_id = "exp_20261025_cicids2017_rf_primary"
    primary_run_dir = os.path.join(EXPERIMENTS_DIR, "primary_rf")

    primary_result = run_experiment(
        run_id=primary_run_id,
        train_path="services/ml-engine/data/processed/train.csv.gz",
        val_path="services/ml-engine/data/processed/val.csv.gz",
        test_path="services/ml-engine/data/processed/test.csv.gz",
        audit_path="services/ml-engine/data/processed/cleaning_audit_report.json",
        manifest_path="services/ml-engine/data/processed/split_manifest.json",
        archive_path="services/ml-engine/data/cicids2017/dataset.zip",
        run_output_dir=primary_run_dir,
        baseline_production_hashes=baseline_hashes,
        random_seed=42
    )

    # 3. Run DoS Hulk Ablation
    ablation_result = run_dos_hulk_ablation(
        baseline_production_hashes=baseline_hashes
    )

    print("\n" + "="*70)
    print("BATCH 4 TRAINING AND ABLATION COMPLETE")
    print("="*70)
    print(f"Primary Run:  {primary_result['run_id']}")
    print(f"  Val Acc:    {primary_result['validation_metrics']['accuracy']:.4f}")
    print(f"  Test Acc:   {primary_result['test_metrics']['accuracy']:.4f}")
    print(f"  Test Macro F1: {primary_result['test_metrics']['macro_f1']:.4f}")
    print(f"  Test Normal FPR: {primary_result['test_metrics']['normal_fpr']:.6f}")
    print(f"Ablation Run: {ablation_result['run_id']}")
    print(f"  Val Acc:    {ablation_result['validation_metrics']['accuracy']:.4f}")
    print(f"  Test Acc:   {ablation_result['test_metrics']['accuracy']:.4f}")
    print(f"  Test Macro F1: {ablation_result['test_metrics']['macro_f1']:.4f}")
    print(f"  Test Normal FPR: {ablation_result['test_metrics']['normal_fpr']:.6f}")


if __name__ == "__main__":
    main()
