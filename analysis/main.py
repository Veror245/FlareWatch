import socket
import time
import json
import threading
import queue
from dataclasses import dataclass, field
from collections import defaultdict, deque
import struct

# threat mappings (protocol)
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

failed_logins = defaultdict(deque)  
attacker_states = {} 
ip_threat_scores = defaultdict(int) 
last_alert_time = {} 

event_queue = queue.Queue()       
state_lock = threading.Lock()     

def get_threat_tier(score):
    if score >= 15: return "CRITICAL"
    elif score >= 10: return "HIGH"
    elif score >= 5: return "MEDIUM"
    return "LOW"

#Evaluates a single event for Brute Force patterns.
#Returns an Incident dictionary if an attack is detected, or None.
# NORMAL(default) → AUTH_ATTACK(5 failed logins) → ACCESS( AUTH_ATTACK logs in) → COMPROMISED( ACCESS starts probing system files)
def analyse_threat(current_event):
    ip = current_event.IP
    
    # lowercase to avoid case-sensitive bugs from  JSON
    event_type = current_event.event_type.lower() 
    event_time = current_event.timestamp

    with state_lock:
        # update threat score based on severity
        ip_threat_scores[ip] += current_event.severity
        
        # calculate threat tier based on current score
        current_score = ip_threat_scores[ip]
        threat_tier = get_threat_tier(current_score)
        
        # read current state (default: normal)
        current_state = attacker_states.get(ip, "NORMAL")

        incident = None #incident dictionary to be returned if an attack is detected

        # Auth attack -> Acess
        if current_state == "AUTH_ATTACK" and event_type == "successful_login":
            attacker_states[ip] = "ACCESS"
            incident = {
                "IP": ip,
                "incident_type": "ACCOUNT_TAKEOVER",
                "threat_tier": threat_tier,
                "total_score": current_score,
                "details": "Attacker successfully logged in after a brute force attack."
            }

        #Acess -> Compromised
        elif current_state == "ACCESS" and event_type == "path_traversal":
            attacker_states[ip] = "COMPROMISED"
            incident = {
                "IP": ip,
                "incident_type": "SYSTEM_COMPROMISE",
                "threat_tier": threat_tier,
                "total_score": current_score,
                "details": "Attacker attempting directory traversal after gaining access."
            }

        # detecting Auth attack from normal on >=5 failed logins in 10seconds
        elif event_type == "failed_login":
            failed_logins[ip].append(event_time)
            
            while failed_logins[ip] and failed_logins[ip][0] < event_time - 10:
                failed_logins[ip].popleft()

            if len(failed_logins[ip]) >= 5:
                failed_logins[ip].clear()
                
                # Upgrade their state!
                attacker_states[ip] = "AUTH_ATTACK" 
                
                incident = {
                    "IP": ip,
                    "incident_type": "Brute Force Attack",
                    "threat_tier": threat_tier,
                    "total_score": current_score,
                    "details": "Detected 5 failed login attempts within 10 seconds."
                }
            
        elif current_score >= 15 and current_state != "COMPROMISED":
            attacker_states[ip] = "COMPROMISED" # Prevent duplicate alerts
            incident = {
                "IP": ip,
                "incident_type": "CRITICAL_THREAT_SCORE",
                "threat_tier": threat_tier,
                "total_score": current_score,
                "details": "IP has accumulated a critical history of suspicious behavior."
            }

        # ALERT DEDUPLICATION
        if incident:
            alert_key = (ip, incident["incident_type"])
            time_since_last_alert = event_time - last_alert_time.get(alert_key, 0)
            
            # If less than 60 seconds have passed, suppress the alert
            if time_since_last_alert < 60:
                return None
                
            # Otherwise, update the timer and return the incident to the network loop
            last_alert_time[alert_key] = event_time
            return incident

        return None


def worker_loop(dev1_client):
    while True:
        current_event = event_queue.get() 
        incident = analyse_threat(current_event)
        
        if incident:
            print(f"\nTHREAT DETECTED: {incident['incident_type']} from {incident['IP']}")
            try:
                outbound_json = json.dumps(incident) + "\n"
                dev1_client.sendall(outbound_json.encode('utf-8'))
                print("Successfully forwarded incident to Dev 1 Dashboard!\n")
            except BrokenPipeError:
                print("Dev 1 disconnected unexpectedly.")
                
        event_queue.task_done()

#reads exactly num_bytes from the socket,
def recv_exact(sock, num_bytes):
    data = bytearray()
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def listen_to_rust():
    dev1_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        dev1_client.connect(('127.0.0.1', DEV1_PORT))
        print(f"Connected to Dev 1 Dashboard on port {DEV1_PORT}")
    except ConnectionRefusedError:
        print(f"Failed to connect to Dev 1. Please ensure Dev 1's server is running on port {DEV1_PORT}.")
        return

    NUM_THREADS = 3
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=worker_loop, args=(dev1_client,), daemon=True)
        t.start()

    #server socket to listen to the Rust engine
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', RUST_PORT))
    server.listen(1)
    
    print(f"Threat Engine listening for Rust logs on port {RUST_PORT}...")
    
    # Block and wait for Rust to connect
    conn, addr = server.accept()
    print(f"Rust Engine connected from {addr}")

    buffer = ""

    # Receive loop
    while True:
        # read the 4-byte payload length (Big-endian u32)
        length_bytes = recv_exact(conn, 4)
        if not length_bytes:
            print("Rust connection closed.")
            break
        payload_length = struct.unpack('>I', length_bytes)[0]
        
        # read the 1-byte message type (u8)
        type_bytes = recv_exact(conn, 1)
        msg_type = struct.unpack('>B', type_bytes)[0]
        
        # read the exact remaining payload
        payload = recv_exact(conn, payload_length)
        
        # parse based on type
        if msg_type == 1:  # THREAT[cite: 2]
            # [Threat type u8][IP len u8][IP][REQ len u16][REQ][cite: 2]
            threat_id = struct.unpack('>B', payload[0:1])[0]
            ip_len = struct.unpack('>B', payload[1:2])[0]
            
            ip_start = 2
            ip_end = ip_start + ip_len
            ip_address = payload[ip_start:ip_end].decode('utf-8')
            
            # Map the numeric ID to the string your state machine expects
            event_type_string = INBOUND_THREATS.get(threat_id, "UNKNOWN_THREAT")
            
            # Create your dataclass and queue it
            current_event = Event(IP=ip_address, event_type=event_type_string, severity=5)
            event_queue.put(current_event)
            
        elif msg_type in (0, 2):  # LOG or NOTHREAT[cite: 2]
            # [IP len u8][IP][REQ len u16][REQ][cite: 2]
            ip_len = struct.unpack('>B', payload[0:1])[0]
            ip_address = payload[1:1+ip_len].decode('utf-8')
            
            # We log it, but benign requests might not need full state machine processing
            current_event = Event(IP=ip_address, event_type="LOG", severity=0)
            event_queue.put(current_event)
            
        elif msg_type == 3:  # STATS[cite: 2]
            # [Logs processed u64][Threats detected u64][Logs/sec u32][cite: 2]
            logs, threats, rate = struct.unpack('>QQI', payload)
            print(f"Rust Stats: {logs} logs, {threats} threats, {rate} req/s")

    conn.close()
    dev1_client.close()

if __name__ == "__main__":
    listen_to_rust()