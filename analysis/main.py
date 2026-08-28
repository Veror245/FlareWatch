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