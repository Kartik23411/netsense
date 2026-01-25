import joblib 
import numpy as np
from pathlib import Path

class MLDetector:

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

    def _load_detector(self, attack_type):
        try:
            model_path = self.models_dir / f"{attack_type}_detector.pkl"
            scaler_path = self.models_dir / f"{attack_type}_scaler.pkl" 
            features_path = self.models_dir / f"{attack_type}_features.txt"

            self.detectors[attack_type] = {
                'model': joblib.load(model_path),
                'scaler': joblib.load(scaler_path),
                'features': self._load_features(features_path),
                'name': attack_type.replace('_', ' ').title()
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

                    results.append({
                        'type': detector['name'],
                        'attack_type': attack_type,
                        'confidence': confidence,
                        'severity': self._get_severity(attack_type)
                    })

            except Exception as e:
                print(f"Error analyzing flow for {attack_type}: {e}")
                continue

        return sorted(results, key=lambda x: x['confidence'], reverse=True)

    def _prepare_features(self, flow_features, required_features):
        values = [flow_features.get(feat, 0) for feat in required_features]

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