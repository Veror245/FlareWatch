<<<<<<< HEAD
import socket
import time
import json
import threading
import queue
import struct
from dataclasses import dataclass, field
from collections import defaultdict, deque

# threat and event mappings
INBOUND_THREATS = {
    0: "SQLI", 
    1: "XSS", 
    2: "PATH_TRAVERSAL", 
    3: "COMMAND_INJECTION",
    4: "SENSITIVE_ACCESS", 
    5: "SSRF", 
    6: "LDAP_INJECTION", 
    7: "XXE", 
    8: "HTTP_ANOMALY"
}

INBOUND_EVENTS = {
    0: "LOGIN_FAILED", 
    1: "LOGIN_SUCCESS", 
    2: "ADMIN_ACCESS", 
    3: "SUSPICIOUS_ENDPOINT"
}

OUTBOUND_THREAT_IDS = {
    "BRUTE_FORCE": 9, 
    "CREDENTIAL_ATTACK": 10, 
    "RECON": 11, 
    "ENDPOINT_SCAN": 12,
    "REQUEST_FLOOD": 13, 
    "ACCOUNT_COMPROMISE": 14, 
    "MULTI_STAGE_ATTACK": 15, 
    "ANOMALY": 16,
    "CRITICAL_THREAT_SCORE": 16 
}

@dataclass
class Event:
    IP: str
    event_type: str
    severity: int
    user: str = None
    endpoint: str = None    
    timestamp: float = field(default_factory=time.time) # Automatically provides timestamp if missing
    metadata: dict = field(default_factory=dict)

RUST_PORT = 4001
DEV1_PORT = 4002

# Reconnect/backoff tuning for the Dev 1 connection
RECONNECT_INITIAL_DELAY = 1.0
RECONNECT_MAX_DELAY = 30.0

# Threat score decays over time so a noisy-but-benign IP doesn't stay pinned at CRITICAL forever
SCORE_DECAY_PER_SECOND = 1.0 / 30.0  # 1 point per 30s of inactivity

failed_logins = defaultdict(deque)  # Holds failed login timestamps per IP
attacker_states = {} # holds current attacker state 
#( NORMAL, BRUTE_FORCE, COMPROMISED_ACCESS, COMPROMISED_ADMIN, COMPROMISED_SQLI, CRITICAL_COMPROMISE )
ip_threat_scores = defaultdict(int) # hold overall threat score per IP
ip_last_score_time = {}  # last time each IP's score was touched, used for decay
last_alert_time = {} # Tracks exact timestamp of the last generated alert for deduplication

event_queue = queue.Queue()       
state_lock = threading.Lock()

# Guards writes to the Dev1 socket since multiple worker threads share one connection
dev1_send_lock = threading.Lock()

def get_threat_tier(score):
    if score >= 15: return "CRITICAL"
    elif score >= 10: return "HIGH"
    elif score >= 5: return "MEDIUM"
    return "LOW"

def _decay_score(ip, now):
    # Reduce the IP's score based on elapsed time since it was last touched. Caller must hold state_lock.
    last_time = ip_last_score_time.get(ip, now)
    elapsed = max(0.0, now - last_time)
    if elapsed > 0 and ip in ip_threat_scores:
        decayed = ip_threat_scores[ip] - elapsed * SCORE_DECAY_PER_SECOND
        ip_threat_scores[ip] = max(0, int(decayed))
    ip_last_score_time[ip] = now

# threat pattern/behaviour analysis pipeline

def analyse_threat(current_event):
    ip = current_event.IP
    event_type = current_event.event_type 
    event_time = current_event.timestamp

    with state_lock:
        _decay_score(ip, event_time)  # apply decay before adding this event's severity

        ip_threat_scores[ip] += current_event.severity
        current_score = ip_threat_scores[ip]
        threat_tier = get_threat_tier(current_score)
        current_state = attacker_states.get(ip, "NORMAL")
        incident = None

        # MULTI_STAGE_ATTACK Kill-chain
        if current_state == "COMPROMISED_SQLI" and event_type == "PATH_TRAVERSAL":
            attacker_states[ip] = "CRITICAL_COMPROMISE"
            incident = {"incident_type": "MULTI_STAGE_ATTACK", "details": "Full kill-chain to Path Traversal."}

        elif current_state == "COMPROMISED_ADMIN" and event_type == "SQLI":
            attacker_states[ip] = "COMPROMISED_SQLI"

        # ACCOUNT_COMPROMISE Kill-chain
        elif current_state == "COMPROMISED_ADMIN" and event_type == "SENSITIVE_ACCESS":
            attacker_states[ip] = "CRITICAL_COMPROMISE"
            incident = {"incident_type": "ACCOUNT_COMPROMISE", "details": "Sensitive access after admin login."}

        elif current_state == "COMPROMISED_ACCESS" and event_type == "ADMIN_ACCESS":
            attacker_states[ip] = "COMPROMISED_ADMIN"

        elif current_state == "BRUTE_FORCE" and event_type == "LOGIN_SUCCESS":
            attacker_states[ip] = "COMPROMISED_ACCESS"
            
        # Base BRUTE_FORCE detection
        elif event_type == "LOGIN_FAILED":
            failed_logins[ip].append(event_time)
            
            while failed_logins[ip] and failed_logins[ip][0] < event_time - 10:
                failed_logins[ip].popleft()
                
            if len(failed_logins[ip]) >= 5:
                failed_logins[ip].clear()
                attacker_states[ip] = "BRUTE_FORCE" 
                incident = {"incident_type": "BRUTE_FORCE", "details": "5 failed logins in 10s."}

        # Catch-All Anomaly Score
        elif current_score >= 15 and current_state != "CRITICAL_COMPROMISE":
            attacker_states[ip] = "CRITICAL_COMPROMISE" 
            incident = {"incident_type": "CRITICAL_THREAT_SCORE", "details": "Critical suspicious behavior."}

        # Deduplication & Formatting
        if incident:
            alert_key = (ip, incident["incident_type"])
            if event_time - last_alert_time.get(alert_key, 0) < 60:
                return None
            
            last_alert_time[alert_key] = event_time
            
            # Attach full context before sending to Dev 1
            incident["IP"] = ip
            incident["threat_id"] = OUTBOUND_THREAT_IDS.get(incident["incident_type"], 16)
            incident["threat_tier"] = threat_tier
            incident["total_score"] = current_score
            return incident

    return None

def send_incident(dev1_client, incident):
    # Extracted from worker_loop so the send can be wrapped in dev1_send_lock (see worker_loop)
    # 1. Prepare the payload fields
    threat_id = incident["threat_id"] # u8[cite: 2]

    ip_bytes = incident["IP"].encode('utf-8')
    ip_len = len(ip_bytes) # u8[cite: 2]
    if ip_len > 255:
        # u8 length field can't represent longer values, truncate defensively
        ip_bytes = ip_bytes[:255]
        ip_len = 255

    # Use the 'details' string as the Request payload so Dev 1 can read it
    req_bytes = incident["details"].encode('utf-8')
    if len(req_bytes) > 65535:
        # u16 length field can't represent longer values, truncate defensively
        req_bytes = req_bytes[:65535]
    req_len = len(req_bytes) # u16[cite: 2]

    # 2. Pack the THREAT payload: [Threat type u8][IP len u8][IP][REQ len u16][REQ][cite: 2]
    # Format: > (big-endian), B (u8), B (u8), {ip_len}s (string bytes), H (u16), {req_len}s (string bytes)[cite: 2]
    payload_format = f'>BB{ip_len}sH{req_len}s'
    payload = struct.pack(payload_format, threat_id, ip_len, ip_bytes, req_len, req_bytes)

    # 3. Pack the Header: [4-byte length][1-byte type][cite: 2]
    # Format: > (big-endian), I (u32), B (u8)[cite: 2]
    msg_type = 1 # THREAT[cite: 2]
    total_length = len(payload)
    header = struct.pack('>IB', total_length, msg_type)

    # 4. Fire the raw bytes down the pipeline
    with dev1_send_lock:  # prevent interleaved writes from concurrent worker threads
        dev1_client.sendall(header + payload)

# THREAD WORKERS
def worker_loop(dev1_client, dev1_ok_event):
    while True:
        current_event = event_queue.get() 
        incident = analyse_threat(current_event)
        
        if incident:
            print(f"\nTHREAT DETECTED: {incident['incident_type']} from {incident['IP']}")
            if not dev1_ok_event.is_set():
                # Dev1 connection is known-down, drop the alert instead of raising repeatedly
                print("Dev 1 unavailable, dropping alert.")
            else:
                try:
                    send_incident(dev1_client, incident)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    print("Dev 1 disconnected unexpectedly.")
                    dev1_ok_event.clear()  # signal the reconnect supervisor to take over

        event_queue.task_done()

def recv_exact(sock, num_bytes):
    # receive exact number of bytes from RUST engine
    data = bytearray()
    while len(data) < num_bytes:
        try:
            packet = sock.recv(num_bytes - len(data))
        except (ConnectionResetError, OSError):
            return None  # treat a reset mid-read the same as a clean disconnect
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def _parse_ip_and_optional_fields(payload, offset):
    # Parses [ip_len u8][ip], then opportunistically [endpoint_len u8][endpoint] and
    # [user_len u8][user] if the Rust engine included them in the remaining bytes.
    # Today's wire format doesn't send these, so they'll come back as None until
    # the Rust side is extended to include them.
    ip_len = struct.unpack('>B', payload[offset:offset + 1])[0]
    offset += 1
    ip_address = payload[offset:offset + ip_len].decode('utf-8', errors='replace')
    offset += ip_len

    endpoint = None
    user = None

    if offset < len(payload):
        try:
            endpoint_len = struct.unpack('>B', payload[offset:offset + 1])[0]
            offset += 1
            endpoint = payload[offset:offset + endpoint_len].decode('utf-8', errors='replace')
            offset += endpoint_len
        except (struct.error, IndexError):
            pass

    if offset < len(payload):
        try:
            user_len = struct.unpack('>B', payload[offset:offset + 1])[0]
            offset += 1
            user = payload[offset:offset + user_len].decode('utf-8', errors='replace')
            offset += user_len
        except (struct.error, IndexError):
            pass

    return ip_address, endpoint, user, offset

def connect_to_dev1(dev1_ok_event):
    # Connects (or reconnects) to Dev 1, retrying with backoff. Blocks until connected.
    delay = RECONNECT_INITIAL_DELAY
    while True:
        dev1_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            dev1_client.connect(('127.0.0.1', DEV1_PORT))
            print(f"Connected to Dev 1 Dashboard on port {DEV1_PORT}")
            dev1_ok_event.set()
            return dev1_client
        except (ConnectionRefusedError, OSError):
            print(f"Failed to connect to Dev 1 on port {DEV1_PORT}. Retrying in {delay:.1f}s...")
            time.sleep(delay)
            delay = min(delay * 2, RECONNECT_MAX_DELAY)

def dev1_reconnect_supervisor(dev1_holder, dev1_ok_event):
    # Background thread: whenever the Dev1 connection is marked down, reconnect it
    # without taking down the Rust-facing listener.
    while True:
        dev1_ok_event.wait()  # block while connection is healthy
        dev1_ok_event.clear()
        try:
            dev1_holder[0].close()
        except OSError:
            pass
        dev1_holder[0] = connect_to_dev1(dev1_ok_event)

# receiving/sending data to/from Rust engine and Dev 1 dashboard
def listen_to_rust():
    dev1_ok_event = threading.Event()
    dev1_client = connect_to_dev1(dev1_ok_event)
    dev1_holder = [dev1_client]  # boxed so the supervisor can swap in a reconnected socket

    supervisor = threading.Thread(
        target=dev1_reconnect_supervisor, args=(dev1_holder, dev1_ok_event), daemon=True
    )
    supervisor.start()

    # Small proxy so worker threads always use the current dev1 socket, even after a reconnect
    class Dev1Proxy:
        def sendall(self, data):
            dev1_holder[0].sendall(data)

    dev1_proxy = Dev1Proxy()

    # Spawn background workers
    for _ in range(3):
        t = threading.Thread(target=worker_loop, args=(dev1_proxy, dev1_ok_event), daemon=True)
        t.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', RUST_PORT))
    server.listen(1)
    
    print(f"Threat Engine listening for Rust binary stream on port {RUST_PORT}...")

    # Loop over Rust connections so a drop doesn't take the whole process down
    while True:
        conn, addr = server.accept()
        print(f"Rust Engine connected from {addr}")
        handle_rust_connection(conn)
        print("Rust Engine disconnected. Waiting for reconnect...")

def handle_rust_connection(conn):
    # Runs the original per-connection receive loop; returns when the Rust engine disconnects or errors
    try:
        while True:
            # Read 4-byte payload length
            length_bytes = recv_exact(conn, 4)
            if not length_bytes: break
            payload_length = struct.unpack('>I', length_bytes)[0]
            
            # Read 1-byte message type
            type_bytes = recv_exact(conn, 1)
            if not type_bytes: break  # handle disconnect between length and type bytes
            msg_type = struct.unpack('>B', type_bytes)[0]
            
            # Read remaining payload
            payload = recv_exact(conn, payload_length)
            if payload is None: break  # handle disconnect mid-payload
            
            # Type 1: THREAT
            if msg_type == 1:  
                threat_id = struct.unpack('>B', payload[0:1])[0]
                ip_address, endpoint, user, _ = _parse_ip_and_optional_fields(payload, 1)
                
                event_str = INBOUND_THREATS.get(threat_id, "UNKNOWN_THREAT")
                event_queue.put(Event(
                    IP=ip_address, event_type=event_str, severity=5,
                    user=user, endpoint=endpoint, metadata={"threat_id": threat_id}
                ))
                
            # Type 4: EVENT
            elif msg_type == 4:  
                event_id = struct.unpack('>B', payload[0:1])[0]
                threat_id = struct.unpack('>B', payload[1:2])[0]  # newly added threat_type field
                
                if event_id == 255: 
                    continue  # NO_EVENT flag bypass
                
                # Shift offset to 2 to account for both 1-byte fields
                ip_address, request_str, _ = _parse_payload_data(payload, 2)
                
                event_str = INBOUND_EVENTS.get(event_id, "UNKNOWN_EVENT")
                event_queue.put(Event(
                    IP=ip_address, 
                    event_type=event_str, 
                    severity=0,
                    endpoint=request_str, 
                    metadata={"event_id": event_id, "threat_id": threat_id}
                ))
                
            # Type 0 (LOG) or 2 (NOTHREAT)
            elif msg_type in (0, 2):  
                ip_address, endpoint, user, _ = _parse_ip_and_optional_fields(payload, 0)
                event_queue.put(Event(
                    IP=ip_address, event_type="LOG", severity=0,
                    user=user, endpoint=endpoint
                ))
                
            # Type 3: STATS
            elif msg_type == 3:  
                logs, threats, rate = struct.unpack('>QQI', payload)
                print(f"Rust Stats: {logs} logs, {threats} threats, {rate} req/s")

    except (ConnectionResetError, OSError, struct.error):
        print("Error on Rust connection.")
    finally:
        conn.close()

if __name__ == "__main__":
=======
import socket
import time
import json
import threading
import queue
import struct
from dataclasses import dataclass, field
from collections import defaultdict, deque

# threat and event mappings
INBOUND_THREATS = {
    0: "SQLI", 
    1: "XSS", 
    2: "PATH_TRAVERSAL", 
    3: "COMMAND_INJECTION",
    4: "SENSITIVE_ACCESS", 
    5: "SSRF", 
    6: "LDAP_INJECTION", 
    7: "XXE", 
    8: "HTTP_ANOMALY"
}

INBOUND_EVENTS = {
    0: "LOGIN_FAILED", 
    1: "LOGIN_SUCCESS", 
    2: "ADMIN_ACCESS", 
    3: "SUSPICIOUS_ENDPOINT"
}

OUTBOUND_THREAT_IDS = {
    "BRUTE_FORCE": 9, 
    "CREDENTIAL_ATTACK": 10, 
    "RECON": 11, 
    "ENDPOINT_SCAN": 12,
    "REQUEST_FLOOD": 13, 
    "ACCOUNT_COMPROMISE": 14, 
    "MULTI_STAGE_ATTACK": 15, 
    "ANOMALY": 16,
    "CRITICAL_THREAT_SCORE": 16 
}

@dataclass
class Event:
    IP: str
    event_type: str
    severity: int
    user: str = None
    endpoint: str = None    
    timestamp: float = field(default_factory=time.time) # Automatically provides timestamp if missing
    metadata: dict = field(default_factory=dict)

RUST_PORT = 4001
DEV1_PORT = 4002

# Reconnect/backoff tuning for the Dev 1 connection
RECONNECT_INITIAL_DELAY = 1.0
RECONNECT_MAX_DELAY = 30.0

# Threat score decays over time so a noisy-but-benign IP doesn't stay pinned at CRITICAL forever
SCORE_DECAY_PER_SECOND = 1.0 / 30.0  # 1 point per 30s of inactivity

failed_logins = defaultdict(deque)  # Holds failed login timestamps per IP
attacker_states = {} # holds current attacker state 
#( NORMAL, BRUTE_FORCE, COMPROMISED_ACCESS, COMPROMISED_ADMIN, COMPROMISED_SQLI, CRITICAL_COMPROMISE )
ip_threat_scores = defaultdict(int) # hold overall threat score per IP
ip_last_score_time = {}  # last time each IP's score was touched, used for decay
last_alert_time = {} # Tracks exact timestamp of the last generated alert for deduplication

event_queue = queue.Queue()       
state_lock = threading.Lock()

# Guards writes to the Dev1 socket since multiple worker threads share one connection
dev1_send_lock = threading.Lock()

def get_threat_tier(score):
    if score >= 15: return "CRITICAL"
    elif score >= 10: return "HIGH"
    elif score >= 5: return "MEDIUM"
    return "LOW"

def _decay_score(ip, now):
    # Reduce the IP's score based on elapsed time since it was last touched. Caller must hold state_lock.
    last_time = ip_last_score_time.get(ip, now)
    elapsed = max(0.0, now - last_time)
    if elapsed > 0 and ip in ip_threat_scores:
        decayed = ip_threat_scores[ip] - elapsed * SCORE_DECAY_PER_SECOND
        ip_threat_scores[ip] = max(0, int(decayed))
    ip_last_score_time[ip] = now

# threat pattern/behaviour analysis pipeline

def analyse_threat(current_event):
    ip = current_event.IP
    event_type = current_event.event_type 
    event_time = current_event.timestamp

    with state_lock:
        _decay_score(ip, event_time)  # apply decay before adding this event's severity

        ip_threat_scores[ip] += current_event.severity
        current_score = ip_threat_scores[ip]
        threat_tier = get_threat_tier(current_score)
        current_state = attacker_states.get(ip, "NORMAL")
        incident = None

        # MULTI_STAGE_ATTACK Kill-chain
        if current_state == "COMPROMISED_SQLI" and event_type == "PATH_TRAVERSAL":
            attacker_states[ip] = "CRITICAL_COMPROMISE"
            incident = {"incident_type": "MULTI_STAGE_ATTACK", "details": "Full kill-chain to Path Traversal."}

        elif current_state == "COMPROMISED_ADMIN" and event_type == "SQLI":
            attacker_states[ip] = "COMPROMISED_SQLI"

        # ACCOUNT_COMPROMISE Kill-chain
        elif current_state == "COMPROMISED_ADMIN" and event_type == "SENSITIVE_ACCESS":
            attacker_states[ip] = "CRITICAL_COMPROMISE"
            incident = {"incident_type": "ACCOUNT_COMPROMISE", "details": "Sensitive access after admin login."}

        elif current_state == "COMPROMISED_ACCESS" and event_type == "ADMIN_ACCESS":
            attacker_states[ip] = "COMPROMISED_ADMIN"

        elif current_state == "BRUTE_FORCE" and event_type == "LOGIN_SUCCESS":
            attacker_states[ip] = "COMPROMISED_ACCESS"
            
        # Base BRUTE_FORCE detection
        elif event_type == "LOGIN_FAILED":
            failed_logins[ip].append(event_time)
            
            while failed_logins[ip] and failed_logins[ip][0] < event_time - 10:
                failed_logins[ip].popleft()
                
            if len(failed_logins[ip]) >= 5:
                failed_logins[ip].clear()
                attacker_states[ip] = "BRUTE_FORCE" 
                incident = {"incident_type": "BRUTE_FORCE", "details": "5 failed logins in 10s."}

        # Catch-All Anomaly Score
        elif current_score >= 15 and current_state != "CRITICAL_COMPROMISE":
            attacker_states[ip] = "CRITICAL_COMPROMISE" 
            incident = {"incident_type": "CRITICAL_THREAT_SCORE", "details": "Critical suspicious behavior."}

        # Deduplication & Formatting
        if incident:
            alert_key = (ip, incident["incident_type"])
            if event_time - last_alert_time.get(alert_key, 0) < 60:
                return None
            
            last_alert_time[alert_key] = event_time
            
            # Attach full context before sending to Dev 1
            incident["IP"] = ip
            incident["threat_id"] = OUTBOUND_THREAT_IDS.get(incident["incident_type"], 16)
            incident["threat_tier"] = threat_tier
            incident["total_score"] = current_score
            return incident

    return None

def send_incident(dev1_client, incident):
    # Extracted from worker_loop so the send can be wrapped in dev1_send_lock (see worker_loop)
    # 1. Prepare the payload fields
    threat_id = incident["threat_id"] # u8[cite: 2]

    ip_bytes = incident["IP"].encode('utf-8')
    ip_len = len(ip_bytes) # u8[cite: 2]
    if ip_len > 255:
        # u8 length field can't represent longer values, truncate defensively
        ip_bytes = ip_bytes[:255]
        ip_len = 255

    # Use the 'details' string as the Request payload so Dev 1 can read it
    req_bytes = incident["details"].encode('utf-8')
    if len(req_bytes) > 65535:
        # u16 length field can't represent longer values, truncate defensively
        req_bytes = req_bytes[:65535]
    req_len = len(req_bytes) # u16[cite: 2]

    # 2. Pack the THREAT payload: [Threat type u8][IP len u8][IP][REQ len u16][REQ][cite: 2]
    # Format: > (big-endian), B (u8), B (u8), {ip_len}s (string bytes), H (u16), {req_len}s (string bytes)[cite: 2]
    payload_format = f'>BB{ip_len}sH{req_len}s'
    payload = struct.pack(payload_format, threat_id, ip_len, ip_bytes, req_len, req_bytes)

    # 3. Pack the Header: [4-byte length][1-byte type][cite: 2]
    # Format: > (big-endian), I (u32), B (u8)[cite: 2]
    msg_type = 1 # THREAT[cite: 2]
    total_length = len(payload)
    header = struct.pack('>IB', total_length, msg_type)

    # 4. Fire the raw bytes down the pipeline
    with dev1_send_lock:  # prevent interleaved writes from concurrent worker threads
        dev1_client.sendall(header + payload)

# THREAD WORKERS
def worker_loop(dev1_client, dev1_ok_event):
    while True:
        current_event = event_queue.get() 
        incident = analyse_threat(current_event)
        
        if incident:
            print(f"\nTHREAT DETECTED: {incident['incident_type']} from {incident['IP']}")
            if not dev1_ok_event.is_set():
                # Dev1 connection is known-down, drop the alert instead of raising repeatedly
                print("Dev 1 unavailable, dropping alert.")
            else:
                try:
                    send_incident(dev1_client, incident)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    print("Dev 1 disconnected unexpectedly.")
                    dev1_ok_event.clear()  # signal the reconnect supervisor to take over

        event_queue.task_done()

def recv_exact(sock, num_bytes):
    # receive exact number of bytes from RUST engine
    data = bytearray()
    while len(data) < num_bytes:
        try:
            packet = sock.recv(num_bytes - len(data))
        except (ConnectionResetError, OSError):
            return None  # treat a reset mid-read the same as a clean disconnect
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def _parse_ip_and_optional_fields(payload, offset):
    # Parses [ip_len u8][ip], then opportunistically [endpoint_len u8][endpoint] and
    # [user_len u8][user] if the Rust engine included them in the remaining bytes.
    # Today's wire format doesn't send these, so they'll come back as None until
    # the Rust side is extended to include them.
    ip_len = struct.unpack('>B', payload[offset:offset + 1])[0]
    offset += 1
    ip_address = payload[offset:offset + ip_len].decode('utf-8', errors='replace')
    offset += ip_len

    endpoint = None
    user = None

    if offset < len(payload):
        try:
            endpoint_len = struct.unpack('>B', payload[offset:offset + 1])[0]
            offset += 1
            endpoint = payload[offset:offset + endpoint_len].decode('utf-8', errors='replace')
            offset += endpoint_len
        except (struct.error, IndexError):
            pass

    if offset < len(payload):
        try:
            user_len = struct.unpack('>B', payload[offset:offset + 1])[0]
            offset += 1
            user = payload[offset:offset + user_len].decode('utf-8', errors='replace')
            offset += user_len
        except (struct.error, IndexError):
            pass

    return ip_address, endpoint, user, offset

def connect_to_dev1(dev1_ok_event):
    # Connects (or reconnects) to Dev 1, retrying with backoff. Blocks until connected.
    delay = RECONNECT_INITIAL_DELAY
    while True:
        dev1_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            dev1_client.connect(('127.0.0.1', DEV1_PORT))
            print(f"Connected to Dev 1 Dashboard on port {DEV1_PORT}")
            dev1_ok_event.set()
            return dev1_client
        except (ConnectionRefusedError, OSError):
            print(f"Failed to connect to Dev 1 on port {DEV1_PORT}. Retrying in {delay:.1f}s...")
            time.sleep(delay)
            delay = min(delay * 2, RECONNECT_MAX_DELAY)

def dev1_reconnect_supervisor(dev1_holder, dev1_ok_event):
    # Background thread: whenever the Dev1 connection is marked down, reconnect it
    # without taking down the Rust-facing listener.
    while True:
        dev1_ok_event.wait()  # block while connection is healthy
        dev1_ok_event.clear()
        try:
            dev1_holder[0].close()
        except OSError:
            pass
        dev1_holder[0] = connect_to_dev1(dev1_ok_event)

# receiving/sending data to/from Rust engine and Dev 1 dashboard
def listen_to_rust():
    dev1_ok_event = threading.Event()
    dev1_client = connect_to_dev1(dev1_ok_event)
    dev1_holder = [dev1_client]  # boxed so the supervisor can swap in a reconnected socket

    supervisor = threading.Thread(
        target=dev1_reconnect_supervisor, args=(dev1_holder, dev1_ok_event), daemon=True
    )
    supervisor.start()

    # Small proxy so worker threads always use the current dev1 socket, even after a reconnect
    class Dev1Proxy:
        def sendall(self, data):
            dev1_holder[0].sendall(data)

    dev1_proxy = Dev1Proxy()

    # Spawn background workers
    for _ in range(3):
        t = threading.Thread(target=worker_loop, args=(dev1_proxy, dev1_ok_event), daemon=True)
        t.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', RUST_PORT))
    server.listen(1)
    
    print(f"Threat Engine listening for Rust binary stream on port {RUST_PORT}...")

    # Loop over Rust connections so a drop doesn't take the whole process down
    while True:
        conn, addr = server.accept()
        print(f"Rust Engine connected from {addr}")
        handle_rust_connection(conn)
        print("Rust Engine disconnected. Waiting for reconnect...")

def handle_rust_connection(conn):
    # Runs the original per-connection receive loop; returns when the Rust engine disconnects or errors
    try:
        while True:
            # Read 4-byte payload length
            length_bytes = recv_exact(conn, 4)
            if not length_bytes: break
            payload_length = struct.unpack('>I', length_bytes)[0]
            
            # Read 1-byte message type
            type_bytes = recv_exact(conn, 1)
            if not type_bytes: break  # handle disconnect between length and type bytes
            msg_type = struct.unpack('>B', type_bytes)[0]
            
            # Read remaining payload
            payload = recv_exact(conn, payload_length)
            if payload is None: break  # handle disconnect mid-payload
            
            # Type 1: THREAT
            if msg_type == 1:  
                threat_id = struct.unpack('>B', payload[0:1])[0]
                ip_address, endpoint, user, _ = _parse_ip_and_optional_fields(payload, 1)
                
                event_str = INBOUND_THREATS.get(threat_id, "UNKNOWN_THREAT")
                event_queue.put(Event(
                    IP=ip_address, event_type=event_str, severity=5,
                    user=user, endpoint=endpoint, metadata={"threat_id": threat_id}
                ))
                
            # Type 4: EVENT
            elif msg_type == 4:  
                event_id = struct.unpack('>B', payload[0:1])[0]
                ip_address, endpoint, user, _ = _parse_ip_and_optional_fields(payload, 1)
                
                event_str = INBOUND_EVENTS.get(event_id, "UNKNOWN_EVENT")
                event_queue.put(Event(
                    IP=ip_address, event_type=event_str, severity=0,
                    user=user, endpoint=endpoint, metadata={"event_id": event_id}
                ))
                
            # Type 0 (LOG) or 2 (NOTHREAT)
            elif msg_type in (0, 2):  
                ip_address, endpoint, user, _ = _parse_ip_and_optional_fields(payload, 0)
                event_queue.put(Event(
                    IP=ip_address, event_type="LOG", severity=0,
                    user=user, endpoint=endpoint
                ))
                
            # Type 3: STATS
            elif msg_type == 3:  
                logs, threats, rate = struct.unpack('>QQI', payload)
                print(f"Rust Stats: {logs} logs, {threats} threats, {rate} req/s")

    except (ConnectionResetError, OSError, struct.error):
        print("Error on Rust connection.")
    finally:
        conn.close()

if __name__ == "__main__":
>>>>>>> 720c0c7274b8a063350fcbba660a8c4557e5a7db
    listen_to_rust()