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
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

RUST_PORT = 4001
DEV1_PORT = 4002

# Reconnect/backoff tuning for the Dev 1 connection
RECONNECT_INITIAL_DELAY = 1.0
RECONNECT_MAX_DELAY = 30.0
SCORE_DECAY_PER_SECOND = 1.0 / 30.0  

failed_logins = defaultdict(deque)  
attacker_states = {} 
ip_threat_scores = defaultdict(int) 
ip_last_score_time = {}  
last_alert_time = {} 

event_queue = queue.Queue()       
state_lock = threading.Lock()
dev1_send_lock = threading.Lock()

def get_threat_tier(score):
    if score >= 15: return "CRITICAL"
    elif score >= 10: return "HIGH"
    elif score >= 5: return "MEDIUM"
    return "LOW"

def _decay_score(ip, now):
    last_time = ip_last_score_time.get(ip, now)
    elapsed = max(0.0, now - last_time)
    if elapsed > 0 and ip in ip_threat_scores:
        decayed = ip_threat_scores[ip] - elapsed * SCORE_DECAY_PER_SECOND
        ip_threat_scores[ip] = max(0, int(decayed))
    ip_last_score_time[ip] = now

def analyse_threat(current_event):
    ip = current_event.IP
    event_type = current_event.event_type 
    event_time = current_event.timestamp

    with state_lock:
        _decay_score(ip, event_time) 

        ip_threat_scores[ip] += current_event.severity
        current_score = ip_threat_scores[ip]
        threat_tier = get_threat_tier(current_score)
        current_state = attacker_states.get(ip, "NORMAL")
        incident = None

        if current_state == "COMPROMISED_SQLI" and event_type == "PATH_TRAVERSAL":
            attacker_states[ip] = "CRITICAL_COMPROMISE"
            incident = {"incident_type": "MULTI_STAGE_ATTACK", "details": "Full kill-chain to Path Traversal."}
        elif current_state == "COMPROMISED_ADMIN" and event_type == "SQLI":
            attacker_states[ip] = "COMPROMISED_SQLI"
        elif current_state == "COMPROMISED_ADMIN" and event_type == "SENSITIVE_ACCESS":
            attacker_states[ip] = "CRITICAL_COMPROMISE"
            incident = {"incident_type": "ACCOUNT_COMPROMISE", "details": "Sensitive access after admin login."}
        elif current_state == "COMPROMISED_ACCESS" and event_type == "ADMIN_ACCESS":
            attacker_states[ip] = "COMPROMISED_ADMIN"
        elif current_state == "BRUTE_FORCE" and event_type == "LOGIN_SUCCESS":
            attacker_states[ip] = "COMPROMISED_ACCESS"
        elif event_type == "LOGIN_FAILED":
            failed_logins[ip].append(event_time)
            while failed_logins[ip] and failed_logins[ip][0] < event_time - 10:
                failed_logins[ip].popleft()
            if len(failed_logins[ip]) >= 5:
                failed_logins[ip].clear()
                attacker_states[ip] = "BRUTE_FORCE" 
                incident = {"incident_type": "BRUTE_FORCE", "details": "5 failed logins in 10s."}
        elif current_score >= 15 and current_state != "CRITICAL_COMPROMISE":
            attacker_states[ip] = "CRITICAL_COMPROMISE" 
            incident = {"incident_type": "CRITICAL_THREAT_SCORE", "details": "Critical suspicious behavior."}

        if incident:
            alert_key = (ip, incident["incident_type"])
            if event_time - last_alert_time.get(alert_key, 0) < 60:
                return None
            
            last_alert_time[alert_key] = event_time
            incident["IP"] = ip
            incident["threat_id"] = OUTBOUND_THREAT_IDS.get(incident["incident_type"], 16)
            incident["threat_tier"] = threat_tier
            incident["total_score"] = current_score
            return incident
    return None

def send_incident(dev1_client, incident):
    threat_id = incident["threat_id"] 
    ip_bytes = incident["IP"].encode('utf-8')
    ip_len = len(ip_bytes) 
    if ip_len > 255:
        ip_bytes = ip_bytes[:255]
        ip_len = 255

    req_bytes = incident["details"].encode('utf-8')
    if len(req_bytes) > 65535:
        req_bytes = req_bytes[:65535]
    req_len = len(req_bytes) 

    payload_format = f'>BB{ip_len}sH{req_len}s'
    payload = struct.pack(payload_format, threat_id, ip_len, ip_bytes, req_len, req_bytes)

    msg_type = 1 
    total_length = len(payload) + 1 
    header = struct.pack('>IB', total_length, msg_type)

    print(f"\n[SEND OUTBOUND] DEV1 ALERT: {incident['incident_type']} | IP: {incident['IP']} | Context: {incident['details']}")

    with dev1_send_lock:  
        dev1_client.sendall(header + payload)

def worker_loop(dev1_client, dev1_ok_event):
    while True:
        current_event = event_queue.get() 
        incident = analyse_threat(current_event)
        
        if incident:
            if not dev1_ok_event.is_set():
                print(f"[ALERT DROPPED] Dev 1 unavailable! Could not send {incident['incident_type']}")
            else:
                try:
                    send_incident(dev1_client, incident)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    print("Dev 1 disconnected unexpectedly.")
                    dev1_ok_event.clear()  
        event_queue.task_done()

def recv_exact(sock, num_bytes):
    if num_bytes == 0:
        return b""
    data = bytearray()
    while len(data) < num_bytes:
        try:
            packet = sock.recv(num_bytes - len(data))
        except (ConnectionResetError, OSError):
            return None  
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def _parse_payload_data(payload, offset):
    ip_len = struct.unpack('>B', payload[offset:offset + 1])[0]
    offset += 1
    ip_address = payload[offset:offset + ip_len].decode('utf-8', errors='replace')
    offset += ip_len

    request_str = None
    if offset + 2 <= len(payload):
        req_len = struct.unpack('>H', payload[offset:offset + 2])[0]
        offset += 2
        request_str = payload[offset:offset + req_len].decode('utf-8', errors='replace')
        offset += req_len

    return ip_address, request_str, offset

def connect_to_dev1(dev1_ok_event):
    delay = RECONNECT_INITIAL_DELAY
    while True:
        dev1_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            dev1_client.connect(('127.0.0.1', DEV1_PORT))
            print(f"✅ [NETWORK] Connected OUTBOUND to Dev 1 Dashboard on port {DEV1_PORT}")
            dev1_ok_event.set()
            return dev1_client
        except (ConnectionRefusedError, OSError):
            print(f"⏳ [NETWORK] Waiting for Dev 1 on port {DEV1_PORT}. Retrying in {delay:.1f}s...")
            time.sleep(delay)
            delay = min(delay * 2, RECONNECT_MAX_DELAY)

def dev1_reconnect_supervisor(dev1_holder, dev1_ok_event):
    while True:
        dev1_ok_event.wait()  
        dev1_ok_event.clear()
        try:
            dev1_holder[0].close()
        except OSError:
            pass
        dev1_holder[0] = connect_to_dev1(dev1_ok_event)

def listen_to_rust():
    dev1_ok_event = threading.Event()
    dev1_client = connect_to_dev1(dev1_ok_event)
    dev1_holder = [dev1_client]  

    supervisor = threading.Thread(
        target=dev1_reconnect_supervisor, args=(dev1_holder, dev1_ok_event), daemon=True
    )
    supervisor.start()

    class Dev1Proxy:
        def sendall(self, data):
            dev1_holder[0].sendall(data)
    dev1_proxy = Dev1Proxy()

    for _ in range(3):
        t = threading.Thread(target=worker_loop, args=(dev1_proxy, dev1_ok_event), daemon=True)
        t.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', RUST_PORT))
    server.listen(1)
    
    print(f"[NETWORK] Threat Engine listening for INBOUND Rust binary stream on port {RUST_PORT}...")

    while True:
        conn, addr = server.accept()
        print(f"[NETWORK] Rust Engine INBOUND connection established from {addr}")
        
        if dev1_ok_event.is_set():
            print(f"\n🎉 [PIPELINE ACTIVE] ALL SYSTEMS SYNCHRONIZED! (Rust -> :4001 -> Python -> :4002 -> Dev 1)\n")

        handle_rust_connection(conn)
        print("[NETWORK] Rust Engine disconnected. Waiting for reconnect...")


def handle_rust_connection(conn):
    try:
        while True:
            length_bytes = recv_exact(conn, 4)
            if not length_bytes: break
            payload_length = struct.unpack('>I', length_bytes)[0]
            if payload_length < 1:
                print(f"[PROTOCOL ERROR] Invalid payload length: {payload_length}")
                break
            
            type_bytes = recv_exact(conn, 1)
            if not type_bytes: break 
            msg_type = struct.unpack('>B', type_bytes)[0]
            
            # FATAL BUG FIX: payload_length INCLUDES the 1-byte message type. 
            # We must only read `payload_length - 1` bytes for the remainder!
            actual_payload_len = payload_length - 1
            payload = recv_exact(conn, actual_payload_len)
            if payload is None and actual_payload_len > 0: break 
            
            try:
                # Type 1: THREAT
                if msg_type == 1:  
                    threat_id = struct.unpack('>B', payload[0:1])[0]
                    if threat_id != 255:  
                        ip_address, request_str, _ = _parse_payload_data(payload, 1)
                        event_str = INBOUND_THREATS.get(threat_id, "UNKNOWN_THREAT")
                        print(f"[RECV THREAT] Type: {event_str:<18} | IP: {ip_address:<14} | Req: {request_str}")
                        event_queue.put(Event(IP=ip_address, event_type=event_str, severity=5, endpoint=request_str, metadata={"threat_id": threat_id}))
                    
                # Type 4: EVENT
                elif msg_type == 4:  
                    event_id = struct.unpack('>B', payload[0:1])[0]
                    
                    # BUG FIX FOR RUST (Dev 3): 
                    # tcp_server.rs forgot to send the `[Threat type u8]` byte for EVENTs.
                    # If byte 1 is 255, it's correct. If it's an IP length (< 64), it's the broken format.
                    second_byte = struct.unpack('>B', payload[1:2])[0]
                    if second_byte == 255:
                        offset = 2 # Spec format
                        threat_id = 255
                    else:
                        offset = 1 # Buggy Rust format
                        threat_id = 255
                    
                    if event_id != 255: 
                        ip_address, request_str, _ = _parse_payload_data(payload, offset)
                        event_str = INBOUND_EVENTS.get(event_id, "UNKNOWN_EVENT")
                        print(f"[RECV EVENT]  Type: {event_str:<18} | IP: {ip_address:<14} | Req: {request_str}")
                        event_queue.put(Event(IP=ip_address, event_type=event_str, severity=0, endpoint=request_str, metadata={"event_id": event_id, "threat_id": threat_id}))
                    
                # Type 0 (LOG) or 2 (NOTHREAT)
                elif msg_type in (0, 2):  
                    ip_address, request_str, _ = _parse_payload_data(payload, 0)
                    # NOTE: Uncomment the line below to print ALL regular logs, but be warned: 
                    # 55,000 logs/sec will severely lag your terminal!
                    # print(f"[RECV LOG] IP: {ip_address:<14} | Req: {request_str[:20]}...")
                    event_queue.put(Event(IP=ip_address, event_type="LOG", severity=0, endpoint=request_str))
                    
                # Type 3: STATS
                elif msg_type == 3:  
                    logs, threats, rate = struct.unpack('>QQI', payload)
                    print(f"[RECV STATS] Processed: {logs:,} logs | Detected: {threats:,} threats | Rate: {rate:,} req/s")

            except Exception as parse_err:
                print(f"[PARSE ERROR] Failed to unpack msg_type {msg_type}: {parse_err}")
                print(f"   Raw Payload Hex: {payload.hex()}")
                # Notice we do NOT break here! We catch the error and keep the TCP stream alive.

    except (ConnectionResetError, OSError, struct.error) as e:
        print(f"[CONNECTION ERROR] Rust stream dropped: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    listen_to_rust()