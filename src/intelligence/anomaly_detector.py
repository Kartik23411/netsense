import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os
import time

class AnomalyDetector:
    
    def __init__(self, model_path='models/anomaly_model.pkl'):
        self.model = None
        self.model_path = model_path
        self.baseline_features = []
        self.is_trained = False

        # thresholds for the attacks
        self.port_scan_threshold = 10 # connection to different ports
        self.ddos_threshold = 100 # packets per sec

        # traffic track
        self.connection_tracker = {} #{src_ip: {dst_ports: set, timestamp}}
        self.packet_rates = {} #{srcIP: packet_count}
        self.last_rate_check = time.time()

        self.load_model()

    def extract_features(self, packet_info):
        """
        Extracted numerical features from packet for model

        - Packet size
        - Port number (if TCP/UDP)
        - Protocol type (encoded)
        - TTL value
        - Time of day
        - Packet rate (packets/sec)
        """
        features = []
        
        # Packet size
        features.append(packet_info.get('packet_size', 0))
        
        # Port (use dest port, or 0 if not TCP/UDP)
        features.append(packet_info.get('dst_port', 0) or 0)
        
        # Protocol encoding (0=Other, 1=TCP, 2=UDP, 3=ICMP)
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3}
        proto = packet_info.get('protocol_name', packet_info.get('ip_protocol', 'Other'))
        features.append(protocol_map.get(proto, 0))
        
        # TTL
        features.append(packet_info.get('ttl', 0) or 0)
        
        # Time of day (hour, 0-23)
        features.append(time.localtime().tm_hour)
        
        # Packet rate (simplified)
        features.append(self.calculate_packet_rate(packet_info.get('src_ip')))

        features = self.normalize_features(features)
        
        return features
    
    def calculate_packet_rate(self, src_ip):
        # to calculate packets per second from a ip

        if not src_ip:
            return 0
        
        current_time = time.time()

        if current_time - self.last_rate_check > 1.0:
            self.packet_rates.clear()
            self.last_rate_check = current_time

        self.packet_rates[src_ip] = self.packet_rates.get(src_ip, 0) + 1

        return self.packet_rates[src_ip]
    
    def collect_baseline(self, packet_info):
        # to collect baseline features from the raw traffic for training in initial phase
        features = self.extract_features(packet_info)
        self.baseline_features.append(features)

    def train_model(self, contamination=0.05):
        # to train the isolation forest model on the collected baseline features
        if len(self.baseline_features) < 200:
            return False, "Not enough data to train the model."
        
        X = np.array(self.baseline_features)

        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100, 
            max_samples='auto', 
            bootstrap=True
        )
        self.model.fit(X)

        self.is_trained = True
        self.save_model()

        return True, f"Model trained on {len(self.baseline_features)} samples"
    
    def predict_anomaly(self, packet_info):

        if not self.is_trained:
            return None
        
        features = self.extract_features(packet_info)
        X = np.array([features])
        
        # Predict (-1 = anomaly, 1 = normal)
        prediction = self.model.predict(X)[0]
        
        # Get anomaly score (lower = more anomalous)
        score = self.model.score_samples(X)[0]
        
        # Convert to confidence (-0.5 - 0.5 scale) to %
        confidence = max(0.0, min(1.0, (score + 0.5) * 2 ))
        
        return {
            'is_anomaly': prediction == -1,
            'anomaly_score': score,
            'confidence': max(0, min(1, confidence))
        }
    
    def detect_port_scan(self, packet_info):
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')

        if not all([src_ip, dst_ip, dst_port]):
            return False
        
        current_time = time.time()
        key = f"{src_ip}->{dst_ip}"

        if key not in self.connection_tracker:
            self.connection_tracker[key] = {
                'ports': set(),
                'timestamp': current_time
            }

        tracker = self.connection_tracker[key]

        # clear enteries older than 60 seconds
        if current_time - tracker['timestamp'] > 60:
            tracker['ports'].clear()
            tracker['timestamp'] = current_time

        # add ports
        tracker['ports'].add(dst_port)

        # compare with the thresholds
        if len(tracker['ports']) > self.port_scan_threshold:
            return {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'port_count': len(tracker['ports']),
                'description': f"Port scan detected: {src_ip} scanned {len(tracker['ports'])} ports on {dst_ip}"
            }
        
        return None
    
    def detect_ddos(self, packet_info):
        # to detect ddos based on
            # high packet rate from single source
            # many small packets
            # SYN flood patterns

        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        if not src_ip:
            return False
        
        rate = self.packet_rates.get(src_ip, 0)

        if rate > self.ddos_threshold:
            return {
                'type': 'DDOS',
                'severity': 'CRITICAL',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_rate': rate,
                'description': f"DDoS attack suspected from {src_ip} with packet rate {rate} pps"
            }
    
    # analyze the packet and return alerts    
    def analyze(self, packet_info):
        # to provide the list of alerts
        alerts = []

        port_scan = self.detect_port_scan(packet_info)
        if port_scan:
            alerts.append(port_scan)
        ddos = self.detect_ddos(packet_info)
        if ddos:
            alerts.append(ddos)
        
        if self.is_trained:
            anomaly_result = self.predict_anomaly(packet_info)
            if anomaly_result and anomaly_result['is_anomaly']:
                alerts.append({
                    'type': 'ML_ANOMALY',
                    'severity': 'MEDIUM',
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'anomaly_score': anomaly_result['anomaly_score'],
                    'confidence': anomaly_result['confidence'],
                    'description': f"ML MODEL detected unusual pattern (confidence: {anomaly_result['confidence']:.2%}) from {packet_info.get('src_ip')} to {packet_info.get('dst_ip')}"
                }) 
        
        return alerts
            
    def save_model(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'is_trained': self.is_trained,
            'baseline_size': len(self.baseline_features)
        }, self.model_path)
    
    def load_model(self):
        """Load trained model from disk"""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.is_trained = data['is_trained']
                return True
            except:
                return False
        return False
            
    def normalize_features(self, features):
        """
            Normalize features to 0-1 range for better ML performance
            
            Feature and their ranges:
            0: packet_size (0-65535)
            1: port (0-65535)
            2: protocol (0-3)
            3: ttl (0-255)
            4: hour (0-23)
            5: packet_rate (0-1000+)
        """
        normalized = features.copy()

        normalized[0] = min(features[0] / 65536.0, 1.0) # packet size
        normalized[1] = min(features[1] / 65535.0, 1.0) # ports
        normalized[2] = features[2] / 3.0 # protocol (0-3)
        normalized[3] = features[3] / 255.0 # ttl
        normalized[4] = features[4] / 23.0 # hour
        normalized[5] = min(features[5] / 1000.0, 1.0) # packet rate

        return normalized

    def get_statistics(self):
        return {
            'is_trained': self.is_trained,
            'baseline_samples': len(self.baseline_features),
            'tracked_connections': len(self.connection_tracker),
            'active_sources': len(self.packet_rates),
        }
