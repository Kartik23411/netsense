import sqlite3
from datetime import datetime

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
    
    def update_flow(self, flow_id, packet_data):
        query = """
            UPDATE flows
            SET end_time = ?, duration = ?, total_bytes = total_bytes + ?, packet_count = packet_count + 1
            WHERE id = ?;
        """
        end_time = datetime.now().timestamp()
        duration = end_time - packet_data['timestamp']
        
        self.cursor.execute(query, (
            end_time,
            duration,
            packet_data.get('packet_size', 0),
            flow_id
        ))
        self.conn.commit()
    
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
        return stats
    
    def close(self):
        if self.conn: 
            self.conn.close()
            print("DB Closed")
  


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

    # 
    
    db.conn.close()
