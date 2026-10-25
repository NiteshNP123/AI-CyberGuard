"""
Unit and Integration Tests for AI CyberGuard Training & Experiment Pipeline
===========================================================================
Tests metric calculations (Brier, ECE, Normal FPR), group disjointness,
experiment logger schemas, model artifact loading, and production invariance.
"""

import os
import sys
import shutil
import tempfile
import unittest
import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, os.path.dirname(__file__))

from train_experiment import (
    FLOW_FEATURES,
    CLASSES,
    CLASS_TO_CODE,
    CODE_TO_CLASS,
    compute_file_sha256,
    compute_multiclass_brier,
    compute_ece,
    compute_normal_traffic_fpr,
    evaluate_predictions,
    ExperimentLogger,
    verify_production_invariance,
    PRODUCTION_MODELS_DIR,
    PRODUCTION_ARTIFACT_NAMES
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV


class TestTrainExperiment(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ai_cyberguard_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_feature_contract(self):
        """Asserts 15 flow features in exact contract order."""
        self.assertEqual(len(FLOW_FEATURES), 15)
        self.assertEqual(FLOW_FEATURES[0], "flow_duration_ms")
        self.assertEqual(FLOW_FEATURES[-1], "dst_port_ephemeral")
        self.assertEqual(len(CLASSES), 5)
        self.assertEqual(CLASSES[0], "NORMAL")
        self.assertEqual(CLASSES[-1], "BOTNET_ANOMALY")

    def test_multiclass_brier_calculation(self):
        """Tests multi-class Brier score matches analytical sum of squared errors."""
        # 2 samples, 3 classes
        # Sample 0: true=0, pred=[1.0, 0.0, 0.0] -> err = 0^2 + 0^2 + 0^2 = 0
        # Sample 1: true=1, pred=[0.0, 0.5, 0.5] -> err = 0^2 + (0.5-1)^2 + 0.5^2 = 0.25 + 0.25 = 0.5
        # Mean = (0 + 0.5) / 2 = 0.25
        y_true = np.array([0, 1])
        y_prob = np.array([
            [1.0, 0.0, 0.0],
            [0.0, 0.5, 0.5]
        ])
        brier = compute_multiclass_brier(y_true, y_prob, n_classes=3)
        self.assertAlmostEqual(brier, 0.25, places=5)

    def test_ece_calculation(self):
        """Tests Expected Calibration Error calculation."""
        # Perfect calibration: confidence 0.8 with 80% accuracy, confidence 1.0 with 100% accuracy
        y_true = np.array([0, 0, 0, 0, 1, 0, 0])
        # 5 samples with conf 0.8: 4 correct (acc=0.8), 1 incorrect
        # 2 samples with conf 1.0: 2 correct (acc=1.0)
        y_prob = np.array([
            [0.8, 0.2],
            [0.8, 0.2],
            [0.8, 0.2],
            [0.8, 0.2],
            [0.8, 0.2],  # wrong
            [1.0, 0.0],
            [1.0, 0.0]
        ])
        ece = compute_ece(y_true, y_prob, n_bins=10)
        self.assertAlmostEqual(ece, 0.0, places=5)

    def test_normal_traffic_fpr(self):
        """Verifies Normal FPR calculation: (actual NORMAL classified as attack) / (total actual NORMAL)."""
        # True labels: 4 NORMAL (0), 2 ATTACK (1, 2)
        # Predictions: 1 NORMAL misclassified as 1 (attack), 3 NORMAL correct.
        # Attacks: 1 ATTACK misclassified as 0 (evasion, not false positive!), 1 ATTACK correct.
        y_true = np.array([0, 0, 0, 0, 1, 2])
        y_pred = np.array([0, 0, 0, 1, 0, 2])

        fpr = compute_normal_traffic_fpr(y_true, y_pred)
        # Expected: 1 false alarm / 4 actual NORMAL = 0.25
        self.assertEqual(fpr, 0.25)

        # Zero false alarms
        y_pred_perfect = np.array([0, 0, 0, 0, 0, 2])
        self.assertEqual(compute_normal_traffic_fpr(y_true, y_pred_perfect), 0.0)

    def test_group_aware_fold_disjointness(self):
        """Verifies that StratifiedGroupKFold guarantees 0 group leakage across folds."""
        rng = np.random.RandomState(42)
        n_samples = 200
        n_groups = 40
        X = rng.randn(n_samples, 5)
        y = rng.choice([0, 1, 2, 3, 4], size=n_samples)
        groups = rng.choice(np.arange(n_groups), size=n_samples)

        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
        for fold_idx, (tr_idx, val_idx) in enumerate(sgkf.split(X, y, groups)):
            tr_groups = set(groups[tr_idx])
            val_groups = set(groups[val_idx])
            overlap = tr_groups.intersection(val_groups)
            self.assertEqual(len(overlap), 0, f"Leakage detected in fold {fold_idx}")

    def test_experiment_logger_schema_and_append(self):
        """Verifies ExperimentLogger creates valid CSVs with correct headers."""
        logger = ExperimentLogger(base_dir=self.temp_dir)

        # Log training run
        logger.log_training_run(
            run_id="test_run_001",
            start_time_utc="2026-10-25T12:00:00Z",
            end_time_utc="2026-10-25T12:05:00Z",
            status="SUCCESS",
            error_message="",
            git_revision="test_rev",
            dataset_archive_sha256="TEST_HASH",
            split_manifest_sha256="TEST_MANIFEST_HASH",
            random_seed=42,
            model_class="RandomForestClassifier",
            model_parameters={"n_estimators": 10},
            software_versions={"python": "3.13"},
            run_dir=self.temp_dir,
            artifact_paths={"model": "path/to/model"}
        )

        runs_df = pd.read_csv(logger.runs_csv)
        self.assertEqual(len(runs_df), 1)
        self.assertEqual(runs_df.iloc[0]["run_id"], "test_run_001")
        self.assertEqual(runs_df.iloc[0]["status"], "SUCCESS")

        # Log experiment metrics
        eval_metrics = {
            "sample_count": 100,
            "accuracy": 0.99,
            "balanced_accuracy": 0.98,
            "macro_precision": 0.97,
            "macro_recall": 0.98,
            "macro_f1": 0.975,
            "weighted_precision": 0.99,
            "weighted_recall": 0.99,
            "weighted_f1": 0.99,
            "normal_fpr": 0.001,
            "brier_score": 0.01,
            "ece": 0.005
        }
        logger.log_experiment_metrics(
            run_id="test_run_001",
            partition="validation",
            metrics=eval_metrics,
            train_duration_sec=1.5,
            inference_duration_sec=0.2,
            model_artifact_sha256="M_HASH",
            scaler_artifact_sha256="S_HASH"
        )

        metrics_df = pd.read_csv(logger.metrics_csv)
        self.assertEqual(len(metrics_df), 1)
        self.assertEqual(metrics_df.iloc[0]["run_id"], "test_run_001")
        self.assertAlmostEqual(float(metrics_df.iloc[0]["accuracy"]), 0.99, places=2)

    def test_model_artifact_saving_loading_and_inference(self):
        """Tests that candidate model and scaler can be dumped, reloaded, and infer correctly."""
        rng = np.random.RandomState(42)
        X = rng.randn(50, 15)
        y = rng.choice(list(range(5)), size=50)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        rf = RandomForestClassifier(n_estimators=5, max_depth=3, random_state=42)
        rf.fit(X_scaled, y)

        model_path = os.path.join(self.temp_dir, "test_model.joblib")
        scaler_path = os.path.join(self.temp_dir, "test_scaler.joblib")

        joblib.dump(rf, model_path)
        joblib.dump(scaler, scaler_path)

        loaded_model = joblib.load(model_path)
        loaded_scaler = joblib.load(scaler_path)

        test_row = rng.randn(1, 15)
        test_scaled = loaded_scaler.transform(test_row)
        pred = loaded_model.predict(test_scaled)
        prob = loaded_model.predict_proba(test_scaled)

        self.assertEqual(pred.shape, (1,))
        self.assertIn(pred[0], list(range(5)))
        self.assertEqual(prob.shape, (1, 5))
        self.assertAlmostEqual(float(np.sum(prob)), 1.0, places=4)

    def test_production_invariance_verification(self):
        """Verifies that production artifacts exist and match current filesystem hashes."""
        baseline_hashes = {
            fname: compute_file_sha256(os.path.join(PRODUCTION_MODELS_DIR, fname))
            for fname in PRODUCTION_ARTIFACT_NAMES
        }
        self.assertTrue(verify_production_invariance(baseline_hashes))


if __name__ == "__main__":
    unittest.main()
