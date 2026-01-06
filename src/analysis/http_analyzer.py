class HTTPAnalyzer:

    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"]

    HTTP_STATUS = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }

    def __init__(self):
        self.http_requests = []
        self.http_responses = []
        self.tls_handshakes = []
        self.https_connections = []

    def analyze(self, packet):

        result = None
        # http (plain text)
        if packet.haslayer('TCP') and packet.haslayer('Raw'):
            result = self.detect_http(packet)
        # https (TLS)
        if packet.haslayer('TCP') and not result:
            result = self.detect_tls(packet)

        return result
    
    def detect_http(self, packet):
        
        try:
            payload = bytes(packet['Raw'].load).decode('utf-8', errors='ignore')

            for method in self.HTTP_METHODS:
                # for the http request
                if payload.startswith(method + ' '):
                    return self.parse_http_request(payload, packet)
                # for the http response
                if payload.startswith('HTTP/'):
                    return self.parse_http_response(payload, packet)

        except Exception as e:
            pass

        return None
    
    def parse_http_request(self, payload, packet):

        """
        HTTP request
        
        GET /index.html HTTP/1.1
        Host: www.example.com
        User-Agent: Mozilla/5.0
        """

        lines = payload.split('\r\n')
        if not lines:
            return None
        
        reques_line = lines[0].split(' ')
        if len(reques_line) < 3:
            return None
        
        method = reques_line[0]
        uri = reques_line[1]
        version = reques_line[2]

        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        host = headers.get('Host', 'Unknown')
        user_agent = headers.get('User-Agent', 'Unknown')

        request_info = {
            'type': 'HTTP_REQUEST',
            'method': method,
            'uri': uri,
            'version': version,
            'host': host,
            'full_url': f"http://{host}{uri}",
            'user_agent': user_agent,
            'src_ip': packet['IP'].src,
            'dst_ip': packet['IP'].dst,
            'src_port': packet['TCP'].sport,
            'dst_port': packet['TCP'].dport,
        }

        self.http_requests.append(request_info)
        return request_info
    
    def parse_http_response(self, payload, packet):
        """
        Parse HTTP response
        
        Example:
        HTTP/1.1 200 OK
        Content-Type: text/html
        Content-Length: 1234
        """

        lines = payload.split('\r\n')
        if not lines:
            return None
        
        status_line = lines[0].split(' ', 2)
        if len(status_line) < 3:
            return None
        
        version = status_line[0]
        status_code = int(status_line[1])
        status_text = status_line[2:]

        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        response_info = {
            'type': 'HTTP_RESPONSE',
            'version': version,
            'status_code': status_code,
            'status_text': self.HTTP_STATUS.get(status_code, status_text),
            'content_type': headers.get('Content-Type', 'unknown'),
            'content_length': headers.get('Content-Length', 'unknown'),
            'src_ip': packet['IP'].src,
            'dst_ip': packet['IP'].dst,
            'src_port': packet['TCP'].sport,
            'dst_port': packet['TCP'].dport,
        }

        self.http_responses.append(response_info)
        return response_info
    
    def detect_tls(self, packet):

        """
        to detect TLS/SSL handshake (HTTPS)
        
        TLS handshake starts with:
        - Byte 0: 0x16 (Handshake)
        - Bytes 1-2: Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
        - Byte 5: 0x01 (Client Hello) or 0x02 (Server Hello)
        """

        if not packet.haslayer('Raw'):
            return None
        
        try:
            payload = bytes(packet['Raw'].load)

            if len(payload) < 6:
                return None
            
            # checking for it is a handshake
            if payload[0] == 0x16:
                tls_version_major = payload[1]
                tls_version_minor = payload[2]
                handshake_type = payload[5]

                version_map = {
                        (3, 1): "TLS 1.0",
                        (3, 2): "TLS 1.1",
                        (3, 3): "TLS 1.2",
                        (3, 4): "TLS 1.3",
                }

                tls_version = version_map.get((tls_version_major, tls_version_minor), "Unknown")

                handshake_map = {
                    0x01: "Client Hello",
                    0x02: "Server Hello",
                    0x0b: "Certificate",
                    0x0c: "Server Key Exchange",
                    0x0e: "Server Hello Done",
                    0x10: "Client Key Exchange",
                }

                handshake_name = handshake_map.get(handshake_type, "Unknown")

                tls_info = {
                    'type': 'TLS_HANDSHAKE',
                    'tls_version': tls_version,
                    'handshake_type': handshake_name,
                    'src_ip': packet['IP'].src,
                    'dst_ip': packet['IP'].dst,
                    'src_port': packet['TCP'].sport,
                    'dst_port': packet['TCP'].dport,
                    'application': 'HTTPS',
                }

                self.tls_handshakes.append(tls_info)

                if handshake_type == 0x01:  # Client Hello
                    self.https_connections.append({
                        'client': packet['IP'].src,
                        'server': packet['IP'].dst,
                        'port': packet['TCP'].dport,
                        'tls_version': tls_version,
                    })

                return tls_info
            
        except Exception as e:
            pass

        return None
    
    def get_statistics(self):
        return {
            'http_requests': len(self.http_requests),
            'http_responses': len(self.http_responses),
            'https_connections': len(self.https_connections),
            'tls_handshakes': len(self.tls_handshakes),
        }