"""
ML Engine Module — Risk Prediction & Behavioral Profiling
Uses sklearn RandomForestRegressor for risk scoring and IsolationForest for anomaly detection.
Both models train on synthetic baselines and fail gracefully if sklearn is unavailable.
"""

import numpy as np
import warnings

try:
    from sklearn.ensemble import RandomForestRegressor, IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[ML Engine] WARNING: scikit-learn not installed. ML features disabled.")


class RiskPredictor:
    """
    Predicts a risk score (0-100) from security analysis features using RandomForestRegressor.
    Features: external_ips_count, mitre_techniques_count, anomaly_score, ioc_reputation_score, event_frequency
    """

    def __init__(self):
        self.model = None
        self.feature_names = [
            "external_ips_count",
            "mitre_techniques_count",
            "anomaly_score",
            "ioc_reputation_score",
            "event_frequency"
        ]
        if SKLEARN_AVAILABLE:
            self._train_on_synthetic_data()

    def _train_on_synthetic_data(self):
        """Train on synthetic labeled data representing known risk scenarios."""
        np.random.seed(42)
        n_samples = 200

        # Generate synthetic features
        X = np.column_stack([
            np.random.randint(0, 10, n_samples),       # external_ips_count
            np.random.randint(0, 8, n_samples),         # mitre_techniques_count
            np.random.uniform(0, 100, n_samples),       # anomaly_score
            np.random.uniform(0, 100, n_samples),       # ioc_reputation_score (higher = worse)
            np.random.uniform(0.1, 50, n_samples),      # event_frequency
        ])

        # Synthetic risk formula — weighted combination with noise
        y = np.clip(
            (X[:, 0] * 3) +                 # more external IPs = higher risk
            (X[:, 1] * 8) +                 # more MITRE techniques = higher risk
            (X[:, 2] * 0.3) +               # anomaly score contribution
            (X[:, 3] * 0.2) +               # IOC reputation contribution
            (X[:, 4] * 0.5) +               # event frequency
            np.random.normal(0, 5, n_samples),  # noise
            0, 100
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.model = RandomForestRegressor(n_estimators=50, max_depth=8, random_state=42)
            self.model.fit(X, y)

        print("[ML Engine] RiskPredictor trained successfully.")

    def extract_features(self, analysis: dict) -> list:
        """Extract the 5 input features from a RAG analysis result dict."""
        techniques = analysis.get("likely_mitre_techniques", [])
        anomalies = analysis.get("anomalies", [])
        retrieval_scores = analysis.get("retrieval_scores", [])

        # external_ips_count — count unique IPs mentioned (rough heuristic)
        import re
        text = analysis.get("attack_explanation", "")
        ip_matches = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
        external_ips = len(set(ip_matches))

        # mitre_techniques_count
        mitre_count = len(techniques)

        # anomaly_score — from anomalies list length or default
        anomaly_score = min(len(anomalies) * 25, 100) if anomalies else 20

        # ioc_reputation_score — derive from severity
        severity_map = {"Critical": 95, "High": 75, "Medium": 50, "Low": 20}
        ioc_score = severity_map.get(analysis.get("severity_rating", ""), 40)

        # event_frequency — from retrieval confidence (higher confidence = more evidence = more events)
        avg_retrieval = float(np.mean(retrieval_scores)) if retrieval_scores else 0.5
        event_freq = avg_retrieval * 30  # scale to reasonable range

        return [external_ips, mitre_count, anomaly_score, ioc_score, event_freq]

    def predict(self, analysis: dict) -> float:
        """Predict risk score (0-100) from analysis dict."""
        if not self.model:
            return 50.0  # default if model unavailable

        try:
            features = self.extract_features(analysis)
            X = np.array([features])
            score = float(self.model.predict(X)[0])
            return round(max(0, min(100, score)), 1)
        except Exception as e:
            print(f"[ML Engine] Prediction error: {e}")
            return 50.0


class BehaviorProfiler:
    """
    Detects anomalous behavior patterns using IsolationForest.
    Learns from event frequency/timing and flags deviations.
    """

    def __init__(self, retrain_interval=10):
        self.model = None
        self.observations = []
        self.retrain_interval = retrain_interval
        self._observation_count = 0

        if SKLEARN_AVAILABLE:
            self._train_baseline()

    def _train_baseline(self):
        """Train on synthetic normal behavior baseline."""
        np.random.seed(99)
        n = 50

        # Normal baseline: low technique counts, moderate event freq, low anomaly indicators
        baseline = np.column_stack([
            np.random.poisson(2, n),            # techniques_count (normally ~2)
            np.random.normal(5, 2, n),          # events_per_minute (normally ~5)
            np.random.uniform(0, 30, n),        # anomaly_indicators (normally low)
            np.random.uniform(10, 40, n),       # ioc_score (normally low-mid)
        ])

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=99
            )
            self.model.fit(baseline)

        print("[ML Engine] BehaviorProfiler baseline trained.")

    def _extract_behavior_features(self, analysis: dict) -> list:
        """Extract behavioral features from an analysis result."""
        techniques = analysis.get("likely_mitre_techniques", [])
        anomalies = analysis.get("anomalies", [])
        retrieval_scores = analysis.get("retrieval_scores", [])

        techniques_count = len(techniques)
        # Simulate events_per_minute from retrieval score density
        avg_score = float(np.mean(retrieval_scores)) if retrieval_scores else 0.5
        events_per_min = avg_score * 15

        anomaly_indicators = len(anomalies) * 20 if anomalies else 10

        severity_map = {"Critical": 90, "High": 70, "Medium": 45, "Low": 15}
        ioc_score = severity_map.get(analysis.get("severity_rating", ""), 30)

        return [techniques_count, events_per_min, anomaly_indicators, ioc_score]

    def update_and_score(self, analysis: dict) -> float:
        """
        Update the profiler with new observation and return anomaly score (0-100).
        Higher score = more anomalous.
        """
        if not self.model:
            return 25.0  # default if model unavailable

        try:
            features = self._extract_behavior_features(analysis)
            self.observations.append(features)
            self._observation_count += 1

            # Score current observation
            X = np.array([features])
            raw_score = self.model.decision_function(X)[0]

            # IsolationForest decision_function: negative = anomalous, positive = normal
            # Convert to 0-100 scale where higher = more anomalous
            anomaly_score = round(max(0, min(100, 50 - (raw_score * 50))), 1)

            # Retrain periodically with accumulated observations
            if self._observation_count % self.retrain_interval == 0 and len(self.observations) >= 20:
                self._retrain()

            return anomaly_score

        except Exception as e:
            print(f"[ML Engine] Behavior scoring error: {e}")
            return 25.0

    def _retrain(self):
        """Retrain model on accumulated observations."""
        try:
            X = np.array(self.observations[-100:])  # use last 100 observations
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self.model.fit(X)
            print(f"[ML Engine] BehaviorProfiler retrained on {len(X)} observations.")
        except Exception as e:
            print(f"[ML Engine] Retrain error: {e}")


# --- Module-level singletons (created on import) ---
risk_predictor = RiskPredictor()
behavior_profiler = BehaviorProfiler()
