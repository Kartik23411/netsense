import sqlite3
from datetime import datetime
import numpy as np

class NetSenseDB:

    def __init__(self, db_path='netsense.db'):
        # Initialization 
        self.conn = sqlite3.connect(db_path)
        # Setting the row factory 
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        # Enable foreign keys
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.create_tables()

    def create_tables(self):
        print("Creating database tables if they do not exist...")
        #  packets table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                
                -- Layer 2
                src_mac TEXT,
                dst_mac TEXT,
                ether_type TEXT,
                
                -- Layer 3
                src_ip TEXT,
                dst_ip TEXT,
                ip_protocol TEXT,
                ttl INTEGER,
                
                -- Layer 4
                src_port INTEGER,
                dst_port INTEGER,
                tcp_flags TEXT,
                
                -- Metadata
                packet_size INTEGER,
                interface TEXT,
                
                -- Reference to flow
                flow_id INTEGER,
                
                FOREIGN KEY (flow_id) REFERENCES flows(id)
            );"""
        )
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ports ON packets(src_port, dst_port);
        """)

        # flows table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                
                -- 5-tuple (uniquely identifies flow)
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                
                -- Timing
                start_time REAL NOT NULL,
                end_time REAL,
                duration REAL,
                
                -- Statistics
                total_bytes INTEGER DEFAULT 0,
                packet_count INTEGER DEFAULT 0,
                
                -- ML features for the phase 2 detection using the flow analysis
                            
                --packet direction tracking
                fwd_packet_count INTEGER DEFAULT 0,
                bwd_packet_count INTEGER DEFAULT 0,
                fwd_bytes INTEGER DEFAULT 0,
                bwd_bytes INTEGER DEFAULT 0,

                -- TCP flags
                syn_count INTEGER DEFAULT 0,
                psh_count INTEGER DEFAULT 0,
                ack_count INTEGER DEFAULT 0,
                fin_count INTEGER DEFAULT 0,
                rst_count INTEGER DEFAULT 0,

                -- TCP window sizes
                init_win_bytes_forward INTEGER DEFAULT 0,
                init_win_bytes_backward INTEGER DEFAULT 0,

                -- Packet length statistics
                fwd_pkt_len_sum REAL DEFAULT 0,
                fwd_pkt_len_sum_sq REAL DEFAULT 0,  -- For std calculation
                bwd_pkt_len_sum REAL DEFAULT 0,
                bwd_pkt_len_sum_sq REAL DEFAULT 0,

                -- inter-arrival time tracking
                last_fwd_packet_time REAL,
                last_bwd_packet_time REAL,
                fwd_iat_sum REAL DEFAULT 0,
                fwd_iat_sum_sq REAL DEFAULT 0,
                fwd_iat_min REAL,
                bwd_iat_sum REAL DEFAULT 0,
                bwd_iat_sum_sq REAL DEFAULT 0,
                bwd_iat_min REAL,
                flow_iat_sum REAL DEFAULT 0,
                flow_iat_sum_sq REAL DEFAULT 0,
                flow_iat_min REAL,
                            
                -- Add active/idle time tracking
                last_packet_time REAL,
                active_time_sum REAL DEFAULT 0,
                active_count INTEGER DEFAULT 0,
                idle_time_sum REAL DEFAULT 0,
                idle_count INTEGER DEFAULT 0,    
                                                   
                -- Application layer
                application TEXT,  -- e.g., "HTTPS", "DNS", "SSH"
                
                -- State
                state TEXT DEFAULT 'ACTIVE'
            );
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_flow_ips ON flows(src_ip, dst_ip);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_flow_time ON flows(start_time);
        """)

        # alert table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                
                -- Alert details
                severity TEXT NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW
                alert_type TEXT NOT NULL,  -- e.g., "Port Scan", "DDoS"
                description TEXT,
                
                -- Context
                src_ip TEXT,
                dst_ip TEXT,
                related_flow_id INTEGER,
                
                -- Status
                acknowledged BOOLEAN DEFAULT 0,
                
                FOREIGN KEY (related_flow_id) REFERENCES flows(id)
            );            
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(timestamp);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);                                        
        """)

        # statistics table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                
                -- Time window
                window_start REAL NOT NULL,
                window_end REAL NOT NULL,
                
                -- Metrics
                total_packets INTEGER,
                total_bytes INTEGER,
                bandwidth_bps REAL,  -- bits per second
                
                -- Protocol breakdown
                tcp_count INTEGER,
                udp_count INTEGER,
                other_count INTEGER,
                
                -- Top talkers (JSON or comma-separated)
                top_applications TEXT
            );
        """)
        # indexes for the statistics table
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_stats_time ON statistics(window_start, window_end);
        """)

        self.conn.commit()

    def insert_packet(self, packet_data):
        query = """
            INSERT INTO packets (timestamp, src_mac, dst_mac, ether_type, src_ip, dst_ip, ip_protocol, ttl, packet_size, interface, src_port, dst_port, tcp_flags, flow_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        self.cursor.execute(query, (
            packet_data['timestamp'],
            packet_data['src_mac'],
            packet_data.get('dst_mac'),
            packet_data.get('ether_type'),
            packet_data.get('src_ip'),
            packet_data.get('dst_ip'),
            packet_data.get('ip_protocol'),
            packet_data.get('ttl'),
            packet_data.get('packet_size'),
            packet_data.get('interface'),
            packet_data.get('src_port'),
            packet_data.get('dst_port'),
            packet_data.get('tcp_flags'),
            packet_data.get('flow_id')
        ))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def get_flow_id(self, src_ip, dst_ip, src_port, dst_port, protocol):
        query = """
            SELECT id from flows
            WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ? AND protocol = ?;
        """
        
        self.cursor.execute(query, (src_ip, dst_ip, src_port, dst_port, protocol))
        result = self.cursor.fetchone()
        # returning if the flow exists otherwise inserting a new flow
        if result:
            return result['id']
        
        insert_query = """
            INSERT INTO flows (src_ip, dst_ip, src_port, dst_port, protocol, start_time)
            VALUES (?, ?, ?, ?, ?, ?);
        """
        self.cursor.execute(insert_query, (src_ip, dst_ip, src_port, dst_port, protocol, datetime.now().timestamp()))
        self.conn.commit()
        return self.cursor.lastrowid

    def update_flow(self, flow_id, packet_data, packet_time):        

        flow = self.get_flow_by_id(flow_id)
    
        # Determine directionis_forward = (
        is_forward = (
            packet_data['src_ip'] == flow['src_ip'] and
            packet_data.get('src_port') == flow['src_port']
        )
        
        # For UDP flows without ports, use IP only
        if packet_data.get('protocol') == 'UDP' and not packet_data.get('src_port'):
            is_forward = (packet_data['src_ip'] == flow['src_i '])
        packet_len = packet_data.get('packet_size', 0)
        
        # Update packet counts and related stats
        if is_forward:
            self.cursor.execute("UPDATE flows SET fwd_packet_count = fwd_packet_count + 1, fwd_bytes = fwd_bytes + ? WHERE id = ?", 
                            (packet_len, flow_id))
            
            # Track packet length stats
            self.cursor.execute("UPDATE flows SET fwd_pkt_len_sum = fwd_pkt_len_sum + ?, fwd_pkt_len_sum_sq = fwd_pkt_len_sum_sq + ? WHERE id = ?", 
                            (packet_len, packet_len**2, flow_id))
            
            # Track IAT
            if flow['last_fwd_packet_time']:
                iat = packet_time - flow['last_fwd_packet_time']
                self.cursor.execute("UPDATE flows SET fwd_iat_sum = fwd_iat_sum + ?, fwd_iat_sum_sq = fwd_iat_sum_sq + ? WHERE id = ?", 
                                (iat, iat**2, flow_id))
                
                # Update min IAT
                if flow['fwd_iat_min'] is None or iat < flow['fwd_iat_min']:
                    self.cursor.execute("UPDATE flows SET fwd_iat_min = ? WHERE id = ?", (iat, flow_id))
            
            self.cursor.execute("UPDATE flows SET last_fwd_packet_time = ? WHERE id = ?", (packet_time, flow_id))
        else:
            # Backward direction
            self.cursor.execute("UPDATE flows SET bwd_packet_count = bwd_packet_count + 1, bwd_bytes = bwd_bytes + ? WHERE id = ?", 
                            (packet_len, flow_id))
            
            # Track packet length stats
            self.cursor.execute("UPDATE flows SET bwd_pkt_len_sum = bwd_pkt_len_sum + ?, bwd_pkt_len_sum_sq = bwd_pkt_len_sum_sq + ? WHERE id = ?", 
                            (packet_len, packet_len**2, flow_id))
            
            # Track IAT
            if flow['last_bwd_packet_time']:
                iat = packet_time - flow['last_bwd_packet_time']
                self.cursor.execute("UPDATE flows SET bwd_iat_sum = bwd_iat_sum + ?, bwd_iat_sum_sq = bwd_iat_sum_sq + ? WHERE id = ?", 
                                (iat, iat**2, flow_id))
                
                # Update min IAT
                if flow['bwd_iat_min'] is None or iat < flow['bwd_iat_min']:
                    self.cursor.execute("UPDATE flows SET bwd_iat_min = ? WHERE id = ?", (iat, flow_id))
            
            self.cursor.execute("UPDATE flows SET last_bwd_packet_time = ? WHERE id = ?", (packet_time, flow_id))
        
        # Track TCP flags
        tcp_flags = packet_data.get('tcp_flags', '')
        if 'S' in tcp_flags:
            self.cursor.execute("UPDATE flows SET syn_count = syn_count + 1 WHERE id = ?", (flow_id,))
        if 'P' in tcp_flags:
            self.cursor.execute("UPDATE flows SET psh_count = psh_count + 1 WHERE id = ?", (flow_id,))
        if 'A' in tcp_flags:
            self.cursor.execute("UPDATE flows SET ack_count = ack_count + 1 WHERE id = ?", (flow_id,))
        if 'F' in tcp_flags:
            self.cursor.execute("UPDATE flows SET fin_count = fin_count + 1 WHERE id = ?", (flow_id,))
        if 'R' in tcp_flags:
            self.cursor.execute("UPDATE flows SET rst_count = rst_count + 1 WHERE id = ?", (flow_id,))
        
        # Track initial window size (first packet only)
        if flow['packet_count'] == 0 and packet_data.get('tcp_window'):
            if is_forward:
                self.cursor.execute("UPDATE flows SET init_win_bytes_forward = ? WHERE id = ?", 
                                (packet_data['tcp_window'], flow_id))
            else:
                self.cursor.execute("UPDATE flows SET init_win_bytes_backward = ? WHERE id = ?", 
                                (packet_data['tcp_window'], flow_id))
        
        # Update flow-level IAT
        if flow['last_packet_time']:
            flow_iat = packet_time - flow['last_packet_time']
            self.cursor.execute("UPDATE flows SET flow_iat_sum = flow_iat_sum + ?, flow_iat_sum_sq = flow_iat_sum_sq + ? WHERE id = ?", 
                            (flow_iat, flow_iat**2, flow_id))
            
            if flow['flow_iat_min'] is None or flow_iat < flow['flow_iat_min']:
                self.cursor.execute("UPDATE flows SET flow_iat_min = ? WHERE id = ?", (flow_iat, flow_id))
        
        # Track active/idle time
        if flow['last_packet_time']:
            time_gap = packet_time - flow['last_packet_time']
            # Defined threshold for active vs idle
            active_threshold = 1.0
            
            if time_gap < active_threshold:     # Active period
                self.cursor.execute("UPDATE flows SET active_time_sum = active_time_sum + ?, active_count = active_count + 1 WHERE id = ?", 
                                (time_gap, flow_id))
            else:
                # Idle period
                self.cursor.execute("UPDATE flows SET idle_time_sum = idle_time_sum + ?, idle_count = idle_count + 1 WHERE id = ?", 
                                (time_gap, flow_id))
        
        self.cursor.execute("UPDATE flows SET last_packet_time = ? WHERE id = ?", (packet_time, flow_id))
        
        # Update basic flow stats (total_bytes, packet_count, end_time, duration)
        duration = packet_time - flow['start_time']

        self.cursor.execute("UPDATE flows SET packet_count = packet_count + 1, total_bytes = total_bytes + ?, end_time = ?, duration = ? WHERE id = ?", 
                        (packet_len, packet_time, duration, flow_id))
        
        # commit the n packets or when the flow ends
        self.packet_counter = getattr(self, 'packet_counter', 0) + 1
        if packet_data.get('tcp_flags') and ('F' in packet_data['tcp_flags'] or 'R' in packet_data['tcp_flags']):
            self.conn.commit()  
        elif self.packet_counter % 100 == 0:
            self.conn.commit()  
    
    def get_flow_by_id(self, flow_id):
        query = "SELECT * FROM flows WHERE id = ?"
        self.cursor.execute(query, (flow_id,))
        result = self.cursor.fetchone()
        return dict(result) if result else None

    def get_packets(self, limit=100, filters=None):
        query = "SELECT * FROM packets WHERE 1=1"
        params = []

        if filters:
            if 'src_ip' in filters:
                query += " AND src_ip = ?"
                params.append(filters['src_ip'])
        
            if 'dst_ip' in filters:
                query += " AND dst_ip = ?"
                params.append(filters['dst_ip'])

            if 'protocol' in filters:
                query += " AND ip_protocol = ?"
                params.append(filters['protocol'])
            
            if 'start_time' in filters:
                query += " AND timestamp >= ?"
                params.append(filters['start_time'])

            if  'end_time' in filters:
                query += " AND timestamp <= ?"
                params.append(filters['end_time'])

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        self.cursor.execute(query, params)
        results = self.cursor.fetchall()
        return [{key: row[key] for key in row.keys()} for row in results]
    
    def get_flows(self, limit=50):
        query = """
            SELECT * from flows
            ORDER BY start_time DESC
            LIMIT ?;
        """ 

        self.cursor.execute(query, (limit,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_statistics(self):
        stats = {}
        # metrices
        self.cursor.execute("SELECT COUNT(*) as total_packets, SUM(packet_size) as total_bytes FROM packets;")
        packet_stats = dict(self.cursor.fetchone())
        stats['total_packets'] = packet_stats.get('total_packets', 0)
        stats['total_bytes'] = packet_stats.get('total_bytes', 0)

        self.cursor.execute("""
            SELECT ip_protocol, COUNT(*) as count FROM packets
            WHERE ip_protocol IS NOT NULL
            GROUP BY ip_protocol
            ORDER BY count DESC;
        """)
        stats['protocol_distribution'] = {row['ip_protocol']: row['count'] for row in self.cursor.fetchall()}
        
        # TCP and UDP counts
        self.cursor.execute("SELECT COUNT(*) as count FROM packets WHERE ip_protocol = 'TCP';")
        stats['tcp_count'] = self.cursor.fetchone()[0] or 0
        
        self.cursor.execute("SELECT COUNT(*) as count FROM packets WHERE ip_protocol = 'UDP';")
        stats['udp_count'] = self.cursor.fetchone()[0] or 0

        # Active flows
        self.cursor.execute("SELECT COUNT(*) as active_flows FROM flows WHERE state = 'ACTIVE';")
        stats['active_flows'] = dict(self.cursor.fetchone())['active_flows']

        # Top talkers
        self.cursor.execute("""
            SELECT src_ip, COUNT(*) as packet_count
            FROM packets
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY packet_count DESC
            LIMIT 5;
        """)
        stats['top_source_ips'] = [dict(row) for row in self.cursor.fetchall()]

        return stats
    
    def insert_alert(self, alert_data):
        """Insert an alert into the alerts table"""
        query = """
            INSERT INTO alerts (timestamp, severity, alert_type, description, src_ip, dst_ip, related_flow_id, acknowledged)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """
        self.cursor.execute(query, (
            alert_data.get('timestamp'),
            alert_data.get('severity'),
            alert_data.get('alert_type'),
            alert_data.get('description'),
            alert_data.get('src_ip'),
            alert_data.get('dst_ip'),
            alert_data.get('related_flow_id'),
            alert_data.get('acknowledged', 0)
        ))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def close(self):
        if self.conn: 
            self.conn.close()
            print("DB Closed")
    
    def get_ml_features(self, flow_id):
        try:
            flow = self.get_flow_by_id(flow_id)
            
            # setting the min. duration for preventing extreme values
            duration = flow['duration'] if flow['duration'] else 0.001
            
            # Better duration estimation for short flows
            if duration < 1.0 and flow['packet_count'] > 2:
                # Estimate: assume ~100ms between packets for short flows
                duration = max(duration, flow['packet_count'] * 0.1)
            
            total_packets = max(flow['packet_count'], 1)
            fwd_packets = flow['fwd_packet_count']
            bwd_packets = flow['bwd_packet_count']

            # Calculate std deviations with the safety check
            fwd_pkt_len_std = self._calculate_std(
                flow['fwd_pkt_len_sum'],
                flow['fwd_pkt_len_sum_sq'],
                fwd_packets
            ) if fwd_packets > 0 else 0
            
            bwd_pkt_len_std = self._calculate_std(
                flow['bwd_pkt_len_sum'],
                flow['bwd_pkt_len_sum_sq'],
                bwd_packets
            ) if bwd_packets > 0 else 0

            # Calculate IAT statistics safely
            flow_iat_count = max(total_packets - 1, 1)
            flow_iat_mean = flow['flow_iat_sum'] / flow_iat_count if flow_iat_count > 0 else 0

            flow_iat_std = self._calculate_std(
                flow['flow_iat_sum'],
                flow['flow_iat_sum_sq'],
                flow_iat_count
            ) if flow_iat_count > 0 else 0
            
            fwd_iat_count = max(fwd_packets - 1, 1)
            fwd_iat_mean = flow['fwd_iat_sum'] / fwd_iat_count if fwd_iat_count > 0 else 0

            fwd_iat_std = self._calculate_std(
                flow['fwd_iat_sum'],
                flow['fwd_iat_sum_sq'],
                fwd_iat_count
            ) if fwd_iat_count > 0 else 0

            bwd_iat_count = max(bwd_packets - 1, 1)
            bwd_iat_mean = flow['bwd_iat_sum'] / bwd_iat_count if bwd_iat_count > 0 else 0

            bwd_iat_std = self._calculate_std(
                flow['bwd_iat_sum'],
                flow['bwd_iat_sum_sq'],
                bwd_iat_count
            ) if bwd_iat_count > 0 else 0
            
            # Active/Idle times with safety
            active_mean = (flow['active_time_sum'] / flow['active_count']) if flow['active_count'] > 0 else 0
            active_min = active_mean  
            
            return {
                # PortScan features
                'Init_Win_bytes_forward': flow['init_win_bytes_forward'],
                'Bwd Packets/s': bwd_packets / duration,
                'PSH Flag Count': flow['psh_count'],
                
                # DDoS features
                'Bwd Packet Length Std': bwd_pkt_len_std,
                'Average Packet Size': flow['total_bytes'] / total_packets,
                'Flow Duration': duration,
                'Flow IAT Std': flow_iat_std,
                
                # DoS Hulk features (subset of DDoS)
                
                # DoS Slowhttp features
                'Active Min': active_min,  # Simplified
                'Active Mean': active_mean,
                
                # DoS GoldenEye features
                'Flow IAT Min': flow['flow_iat_min'] if flow['flow_iat_min'] is not None else 0,
                'Fwd IAT Min': flow['fwd_iat_min'] if flow['fwd_iat_min'] is not None else 0,
                'Flow IAT Mean': flow_iat_mean,
                
                # DoS Slowloris features
                'Fwd IAT Mean': fwd_iat_mean,
                'Bwd IAT Mean': bwd_iat_mean,
            }
        
        except Exception as e:
            print(f"Error extracting features for flow {flow_id}: {e}")
            import traceback
            traceback.print_exc()
            # Return zeros for all expected features
            return {
                'Init_Win_bytes_forward': 0,
                'Bwd Packets/s': 0,
                'PSH Flag Count': 0,
                'Bwd Packet Length Std': 0,
                'Average Packet Size': 0,
                'Flow Duration': 0,
                'Flow IAT Std': 0,
                'Active Min': 0,
                'Active Mean': 0,
                'Flow IAT Min': 0,
                'Fwd IAT Min': 0,
                'Flow IAT Mean': 0,
                'Fwd IAT Mean': 0,
                'Bwd IAT Mean': 0,
            }

    # to calculate standard deviation
    def _calculate_std(self, sum_val, sum_sq, count):
        if count <= 1:
            return 0
        mean = sum_val / count
        variance = (sum_sq / count) - (mean ** 2)
        return max(variance, 0) ** 0.5  


if __name__ == "__main__":
    db = NetSenseDB()
    print("✓ Database and tables created successfully!")
    
    # Verify tables exist
    db.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = db.cursor.fetchall()
    print(f"✓ Tables created: {[t[0] for t in tables]}")
    
    # Verify indexes exist
    db.cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
    indexes = db.cursor.fetchall()
    print(f"✓ Indexes created: {[i[0] for i in indexes]}")
    
    db.conn.close()
