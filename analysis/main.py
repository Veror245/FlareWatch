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