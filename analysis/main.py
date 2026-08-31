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
    8: "HTTP_ANOMALY",
}

INBOUND_EVENTS = {
    0: "LOGIN_FAILED",
    1: "LOGIN_SUCCESS",
    2: "ADMIN_ACCESS",
    3: "SUSPICIOUS_ENDPOINT",
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
    "CRITICAL_THREAT_SCORE": 16,
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
DEV1_PORT = 4004

RECONNECT_INITIAL_DELAY = 1.0
RECONNECT_MAX_DELAY = 30.0
SCORE_DECAY_PER_SECOND = 1.0 / 30.0

# state trackers for complex threat detection
failed_logins = defaultdict(deque)
recon_tracker = defaultdict(deque)
scan_tracker = defaultdict(deque)
flood_tracker = defaultdict(deque)

attacker_states = {}
ip_threat_scores = defaultdict(int)
ip_last_score_time = {}
last_alert_time = {}

event_queue = queue.Queue()
state_lock = threading.Lock()
dev1_send_lock = threading.Lock()


def get_threat_tier(score):
    if score >= 15:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
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

        # 13. REQUEST_FLOOD Tracker
        flood_tracker[ip].append(event_time)
        while flood_tracker[ip] and flood_tracker[ip][0] < event_time - 2.0:
            flood_tracker[ip].popleft()
        if len(flood_tracker[ip]) >= 15:
            flood_tracker[ip].clear()
            incident = {
                "incident_type": "REQUEST_FLOOD",
                "details": "High velocity request flood detected.",
            }

        # 11. RECON Tracker
        if not incident and event_type in ("SENSITIVE_ACCESS", "SUSPICIOUS_ENDPOINT"):
            recon_tracker[ip].append(event_time)
            while recon_tracker[ip] and recon_tracker[ip][0] < event_time - 10.0:
                recon_tracker[ip].popleft()
            if len(recon_tracker[ip]) >= 4:
                recon_tracker[ip].clear()
                incident = {
                    "incident_type": "RECON",
                    "details": "Multiple sensitive endpoints hit.",
                }

        # 12. ENDPOINT_SCAN Tracker
        if not incident and event_type == "SUSPICIOUS_ENDPOINT":
            scan_tracker[ip].append(event_time)
            while scan_tracker[ip] and scan_tracker[ip][0] < event_time - 10.0:
                scan_tracker[ip].popleft()
            if len(scan_tracker[ip]) >= 6:
                scan_tracker[ip].clear()
                incident = {
                    "incident_type": "ENDPOINT_SCAN",
                    "details": "Rapid endpoint scanning behavior.",
                }

        # 16. ANOMALY Tracker
        if not incident and event_type == "HTTP_ANOMALY":
            incident = {
                "incident_type": "ANOMALY",
                "details": "Malformed HTTP request structure.",
            }

        # STATE-BASED KILL-CHAINS (9, 10, 14, 15)
        if not incident:
            if current_state == "COMPROMISED_SQLI" and event_type == "PATH_TRAVERSAL":
                current_state = "CRITICAL_COMPROMISE"
                incident = {
                    "incident_type": "MULTI_STAGE_ATTACK",
                    "details": "Full kill-chain: SQLi to Path Traversal.",
                }
            elif current_state == "COMPROMISED_ADMIN" and event_type == "SQLI":
                current_state = "COMPROMISED_SQLI"
                incident = {
                    "incident_type": "MULTI_STAGE_ATTACK",
                    "details": "Admin privilege escalated to SQLi.",
                }
            elif (
                current_state == "COMPROMISED_ADMIN"
                and event_type == "SENSITIVE_ACCESS"
            ):
                current_state = "CRITICAL_COMPROMISE"
                incident = {
                    "incident_type": "ACCOUNT_COMPROMISE",
                    "details": "Sensitive data accessed after admin login.",
                }
            elif current_state == "COMPROMISED_ACCESS" and event_type == "ADMIN_ACCESS":
                current_state = "COMPROMISED_ADMIN"
                incident = {
                    "incident_type": "ACCOUNT_COMPROMISE",
                    "details": "User escalated to Admin access.",
                }
            elif current_state == "BRUTE_FORCE" and event_type == "LOGIN_SUCCESS":
                current_state = "COMPROMISED_ACCESS"
                incident = {
                    "incident_type": "CREDENTIAL_ATTACK",
                    "details": "Brute force resulted in successful login.",
                }
            elif event_type == "LOGIN_FAILED":
                failed_logins[ip].append(event_time)
                while failed_logins[ip] and failed_logins[ip][0] < event_time - 10:
                    failed_logins[ip].popleft()
                if len(failed_logins[ip]) >= 5:
                    failed_logins[ip].clear()
                    current_state = "BRUTE_FORCE"
                    incident = {
                        "incident_type": "BRUTE_FORCE",
                        "details": "5 failed logins in 10s.",
                    }

        # 16. FALLBACK CATCH-ALL
        if (
            not incident
            and current_score >= 15
            and current_state != "CRITICAL_COMPROMISE"
        ):
            current_state = "CRITICAL_COMPROMISE"
            incident = {
                "incident_type": "CRITICAL_THREAT_SCORE",
                "details": "Critical suspicious behavior threshold met.",
            }

        # Save the updated state
        attacker_states[ip] = current_state

        if incident:
            alert_key = (ip, incident["incident_type"])
            # Lowered cooldown to 5 seconds
            if event_time - last_alert_time.get(alert_key, 0) < 5:
                return None

            last_alert_time[alert_key] = event_time
            incident["IP"] = ip
            incident["threat_id"] = OUTBOUND_THREAT_IDS.get(
                incident["incident_type"], 16
            )
            incident["threat_tier"] = threat_tier
            incident["total_score"] = int(current_score)
            return incident

    return None


def send_incident(dev1_client, incident):
    threat_id = incident["threat_id"]
    ip_bytes = incident["IP"].encode("utf-8")
    ip_len = len(ip_bytes)
    if ip_len > 255:
        ip_bytes = ip_bytes[:255]
        ip_len = 255

    req_bytes = incident["details"].encode("utf-8")
    if len(req_bytes) > 65535:
        req_bytes = req_bytes[:65535]
    req_len = len(req_bytes)

    payload_format = f">BB{ip_len}sH{req_len}s"
    payload = struct.pack(
        payload_format, threat_id, ip_len, ip_bytes, req_len, req_bytes
    )

    msg_type = 1
    total_length = len(payload) + 1
    header = struct.pack(">IB", total_length, msg_type)

    with dev1_send_lock:
        dev1_client.sendall(header + payload)


def worker_loop(dev1_client, dev1_ok_event, dev1_disconnected_event):
    while True:
        current_event = event_queue.get()
        incident = analyse_threat(current_event)

        if incident:
            if dev1_ok_event.is_set():
                try:
                    send_incident(dev1_client, incident)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    if dev1_ok_event.is_set():
                        dev1_ok_event.clear()
                        dev1_disconnected_event.set()
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
    ip_len = struct.unpack(">B", payload[offset : offset + 1])[0]
    offset += 1
    ip_address = payload[offset : offset + ip_len].decode("utf-8", errors="replace")
    offset += ip_len

    request_str = None
    if offset + 2 <= len(payload):
        req_len = struct.unpack(">H", payload[offset : offset + 2])[0]
        offset += 2
        request_str = payload[offset : offset + req_len].decode(
            "utf-8", errors="replace"
        )
        offset += req_len

    return ip_address, request_str, offset


def connect_to_dev1(dev1_ok_event):
    import os

    delay = RECONNECT_INITIAL_DELAY
    while True:
        dev1_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dev1_host = os.environ.get("BACKEND_HOST", "127.0.0.1")
        dev1_addr = (dev1_host, DEV1_PORT)
        try:
            dev1_client.connect(dev1_addr)
            dev1_ok_event.set()
            return dev1_client
        except (ConnectionRefusedError, OSError):
            time.sleep(delay)
            delay = min(delay * 2, RECONNECT_MAX_DELAY)


def dev1_reconnect_supervisor(dev1_holder, dev1_ok_event, dev1_disconnected_event):
    while True:
        dev1_disconnected_event.wait()
        dev1_disconnected_event.clear()
        try:
            dev1_holder[0].close()
        except OSError:
            pass
        dev1_holder[0] = connect_to_dev1(dev1_ok_event)


def listen_to_rust():
    dev1_ok_event = threading.Event()
    dev1_disconnected_event = threading.Event()

    dev1_client = connect_to_dev1(dev1_ok_event)
    dev1_holder = [dev1_client]

    supervisor = threading.Thread(
        target=dev1_reconnect_supervisor,
        args=(dev1_holder, dev1_ok_event, dev1_disconnected_event),
        daemon=True,
    )
    supervisor.start()

    class Dev1Proxy:
        def sendall(self, data):
            dev1_holder[0].sendall(data)

    dev1_proxy = Dev1Proxy()

    for _ in range(3):
        t = threading.Thread(
            target=worker_loop,
            args=(dev1_proxy, dev1_ok_event, dev1_disconnected_event),
            daemon=True,
        )
        t.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", RUST_PORT))
    server.listen(5)

    print(f"Threat Engine permanently listening for Rust stream on port {RUST_PORT}...")

    while True:
        conn, _addr = server.accept()
        threading.Thread(
            target=handle_rust_connection, args=(conn,), daemon=True
        ).start()


def handle_rust_connection(conn):
    try:
        while True:
            length_bytes = recv_exact(conn, 4)
            if not length_bytes:
                break
            payload_length = struct.unpack(">I", length_bytes)[0]
            if payload_length < 1:
                break

            type_bytes = recv_exact(conn, 1)
            if not type_bytes:
                break
            msg_type = struct.unpack(">B", type_bytes)[0]

            actual_payload_len = payload_length - 1
            payload = recv_exact(conn, actual_payload_len)
            if payload is None and actual_payload_len > 0:
                break

            try:
                # Type 1: THREAT
                if msg_type == 1:
                    threat_id = struct.unpack(">B", payload[0:1])[0]
                    if threat_id != 255:
                        ip_address, request_str, _ = _parse_payload_data(payload, 1)
                        event_str = INBOUND_THREATS.get(threat_id, "UNKNOWN_THREAT")
                        event_queue.put(
                            Event(
                                IP=ip_address,
                                event_type=event_str,
                                severity=5,
                                endpoint=request_str,
                                metadata={"threat_id": threat_id},
                            )
                        )

                # Type 4: EVENT
                elif msg_type == 4:
                    event_id = struct.unpack(">B", payload[0:1])[0]

                    second_byte = struct.unpack(">B", payload[1:2])[0]
                    if second_byte == 255:
                        offset = 2
                        threat_id = 255
                    else:
                        offset = 1
                        threat_id = 255

                    if event_id != 255:
                        ip_address, request_str, _ = _parse_payload_data(
                            payload, offset
                        )
                        event_str = INBOUND_EVENTS.get(event_id, "UNKNOWN_EVENT")
                        event_queue.put(
                            Event(
                                IP=ip_address,
                                event_type=event_str,
                                severity=0,
                                endpoint=request_str,
                                metadata={"event_id": event_id, "threat_id": threat_id},
                            )
                        )

                # Type 0 (LOG) or 2 (NOTHREAT)
                elif msg_type in (0, 2):
                    ip_address, request_str, _ = _parse_payload_data(payload, 0)
                    event_queue.put(
                        Event(
                            IP=ip_address,
                            event_type="LOG",
                            severity=0,
                            endpoint=request_str,
                        )
                    )

            except Exception:
                pass

    except (ConnectionResetError, OSError, struct.error):
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    listen_to_rust()

