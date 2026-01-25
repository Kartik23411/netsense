import joblib 
import numpy as np
from pathlib import Path

class MLDetector:

    # adding confidence thresholds for each attack type to reduce false positives
    CONFIDENCE_THRESHOLDS = {
        'portscan': 0.85,       # High confidence - port scans are distinctive
        'ddos': 0.75,           # Moderate - clear volume pattern
        'dos_hulk': 0.80,       # Moderate-high
        'dos_slowloris': 0.90,  # Very high - subtle attack, needs strong signal
        'dos_slowhttp': 0.90,   # Very high - very subtle
        'dos_goldeneye': 0.85   # High
    }

    def __init__(self, models_dir='models'):
        self.models_dir = Path(models_dir)
        self.detectors = {}

        self._load_detector('portscan')
        self._load_detector('ddos')
        self._load_detector('dos_hulk')
        self._load_detector('dos_slowloris')
        self._load_detector('dos_slowhttp')
        self._load_detector('dos_goldeneye')

        print(f"Loaded detectors: {list(self.detectors.keys())}")
        print(f"Confidence thresholds: {self.CONFIDENCE_THRESHOLDS}")

    def _load_detector(self, attack_type):
        try:
            model_path = self.models_dir / f"{attack_type}_detector.pkl"
            scaler_path = self.models_dir / f"{attack_type}_scaler.pkl" 
            features_path = self.models_dir / f"{attack_type}_features.txt"

            self.detectors[attack_type] = {
                'model': joblib.load(model_path),
                'scaler': joblib.load(scaler_path),
                'features': self._load_features(features_path),
                'name': attack_type.replace('_', ' ').title(),
                'threshold': self.CONFIDENCE_THRESHOLDS.get(attack_type, 0.8)
            }
        except Exception as e:
            print(f"Failed to load detector for {attack_type}: {e}")

    def _load_features(self, features_path):
        with open(features_path, 'r') as f:
            return [line.strip() for line in f]
        
    def analyze_flow(self, flow_features):
        results = []

        for attack_type, detector in self.detectors.items():
            try:
                X = self._prepare_features(flow_features, detector['features'])
                X_scaled = detector['scaler'].transform(X)
                prediction = detector['model'].predict(X_scaled)[0]

                if prediction == 1:
                    proba = detector['model'].predict_proba(X_scaled)[0]
                    confidence = proba[1]

                    threshold = detector['threshold']

                    if confidence >= threshold:
                        results.append({
                            'type': detector['name'],
                            'attack_type': attack_type,
                            'confidence': confidence,
                            'severity': self._get_severity(attack_type)
                        })

                    # for the developer: log near-misses for tuning
                    elif confidence >= threshold - 0.1:
                        # print(f"  Near-miss: {attack_type} at {confidence:.1%} (threshold: {threshold:.1%})")
                        pass

            except Exception as e:
                print(f"Error analyzing flow for {attack_type}: {e}")
                import traceback
                traceback.print_exc()
                continue

        return sorted(results, key=lambda x: x['confidence'], reverse=True)

    def _prepare_features(self, flow_features, required_features):
        values = []
        
        for feat in required_features:
            value = flow_features.get(feat, 0)
            # value validation
            if value is None or np.isnan(value) or np.isinf(value):
                value = 0

            values.append(value)

        import pandas as pd
        return pd.DataFrame([values], columns=required_features)

    def _get_severity(self, attack_type):
        severity_map = {
            'portscan': 'HIGH',
            'ddos': 'CRITICAL',
            'dos_hulk': 'CRITICAL',
            'dos_slowhttp': 'HIGH',
            'dos_slowloris': 'HIGH',
            'dos_goldeneye': 'HIGH'
        }
        return severity_map.get(attack_type, 'MEDIUM')

if __name__ == "__main__":
    detector = MLDetector()
    print(f"\n Detector ready with {len(detector.detectors)} models")
    print(f" Statistics: {detector.get_statistics()}")