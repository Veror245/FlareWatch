import socket
import random
import time
import struct
import argparse

HOST = "127.0.0.1"
PORT = 4000
TARGET_RATE = 55_000
BATCH_SIZE = 1000

random.seed()

# ============================================================
# IPs
# ============================================================

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13",
    "192.168.1.14",
    "192.168.1.15",
]

ATTACK_IPS = [
    "10.0.0.5",
    "10.0.0.23",
    "10.0.0.42",
    "172.16.0.99",
    "192.168.1.200",
]

# ============================================================
# Normal requests
# ============================================================

NORMAL_REQUESTS = [
    "GET / HTTP/1.1",
    "GET /home HTTP/1.1",
    "GET /login HTTP/1.1",
    "GET /logout HTTP/1.1",
    "GET /products HTTP/1.1",
    "GET /products/1 HTTP/1.1",
    "GET /products/2 HTTP/1.1",
    "GET /api HTTP/1.1",
    "GET /api/users HTTP/1.1",
    "GET /api/products HTTP/1.1",
    "GET /search?q=laptop HTTP/1.1",
    "GET /about HTTP/1.1",
    "GET /contact HTTP/1.1",
    "GET /dashboard HTTP/1.1",
    "GET /profile HTTP/1.1",
    "GET /settings HTTP/1.1",
]

# ============================================================
# Threat patterns
# ============================================================

SQLI = [
    "' OR 1=1",
    "' OR '1'='1",
    '" OR 1=1',
    '" OR "1"="1"',
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' AND 1=1",
    "' AND '1'='1",
    "' AND 1=2",
    '" AND 1=1',
    '" AND 1=2',
    "UNION SELECT",
    "UNION ALL SELECT",
    "UNION DISTINCT SELECT",
    "UNION SELECT NULL",
    "UNION ALL SELECT NULL",
    "SELECT * FROM",
    "SELECT username",
    "SELECT password",
    "FROM users",
    "FROM information_schema",
    "DROP TABLE",
    "DROP DATABASE",
    "INSERT INTO",
    "DELETE FROM",
    "UPDATE users",
    "ALTER TABLE",
    "OR 1=1",
    "AND 1=1",
    "OR TRUE",
    "AND TRUE",
    "OR 'x'='x",
]

XSS = [
    "<script",
    "</script>",
    "<script>",
    "<script src=",
    "javascript:",
    "javascript://",
    "vbscript:",
    "data:text/html",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onblur=",
    "onchange=",
    "onsubmit=",
    "onkeydown=",
    "onkeyup=",
    "<iframe",
    "<iframe src=",
    "<object",
    "<embed",
    "<svg",
    "<svg onload=",
    "<img src=",
    "<img onerror=",
    "<body onload=",
    "<input onfocus=",
    "<details open",
]

PATH_TRAVERSAL = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../etc/",
    "../../etc/",
    "../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/issue",
    "/proc/self/",
    "proc/self/environ",
    r"..\\",
    r"..\\..\\",
    r"..\\..\\..\\",
    r"..\\windows\\",
    r"..\\windows\\system32",
    "windows/system32",
    "windows/win.ini",
    "win.ini",
    "boot.ini",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%5c",
    "%252e%252e%252f",
]

COMMAND_INJECTION = [
    "; whoami",
    "; id",
    "; ls",
    "; cat",
    "; pwd",
    "| whoami",
    "| id",
    "| ls",
    "&& whoami",
    "&& id",
    "&& ls",
    "|| whoami",
    "|| id",
    "$(whoami)",
    "$(id)",
    "$(cat /etc/passwd)",
    "`whoami`",
    "`id`",
    "`cat /etc/passwd`",
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/dash",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "whoami",
    "/etc/passwd",
    "id",
    "uname -a",
    "ifconfig",
    "ipconfig",
    "netstat",
]

SENSITIVE_ACCESS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/.git/",
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    ".ssh/",
    "wp-config.php",
    "web.config",
    ".htaccess",
    ".htpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
]

SSRF = [
    "localhost",
    "127.0.0.1",
    "127.0.0.0",
    "0.0.0.0",
    "::1",
    "10.0.0.1",
    "10.10.10.10",
    "192.168.1.1",
    "192.168.0.1",
    "172.16.0.1",
    "172.20.0.1",
    "172.31.255.255",
    "169.254.169.254",
    "/latest/meta-data",
    "/latest/user-data",
    "metadata.google.internal",
]

LDAP_INJECTION = [
    "*)(uid=*",
    "*)(cn=*",
    "*)(objectClass=*",
    "(|(uid=",
    "(|(cn=",
    "(&(uid=",
    "(&(cn=",
    "*))",
    "*))(",
]

XXE = [
    "<!DOCTYPE",
    "<!ENTITY",
    'SYSTEM "',
    "SYSTEM '",
    'PUBLIC "',
    "PUBLIC '",
    "file://",
    "php://",
    "expect://",
]

# ============================================================
# Behavioral sequences
# ============================================================


def brute_force_sequence(ip):
    return [
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
    ]


def credential_attack_sequence(ip):
    users = ["admin", "root", "administrator", "test", "guest", "support", "user"]
    return [(ip, f"LOGIN_FAILED user={user}") for user in users]


def account_compromise_sequence(ip):
    return [
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_SUCCESS user=admin"),
        (ip, "ADMIN_ACCESS /admin"),
        (ip, "GET /.env HTTP/1.1"),
    ]


def multi_stage_sequence(ip):
    return [
        (ip, "GET /admin HTTP/1.1"),
        (ip, "GET /login HTTP/1.1"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=root"),
        (ip, "LOGIN_FAILED user=administrator"),
        (ip, "LOGIN_FAILED user=admin"),
        (ip, "LOGIN_FAILED user=root"),
        (ip, "LOGIN_SUCCESS user=admin"),
        (ip, "ADMIN_ACCESS /admin"),
        (ip, "GET /login?id=' OR 1=1-- HTTP/1.1"),
        (ip, "GET /download?file=../../etc/passwd HTTP/1.1"),
    ]


def recon_sequence(ip):
    return [
        (ip, "GET /admin HTTP/1.1"),
        (ip, "GET /.env HTTP/1.1"),
        (ip, "GET /.git/config HTTP/1.1"),
        (ip, "GET /config HTTP/1.1"),
        (ip, "GET /debug HTTP/1.1"),
        (ip, "GET /backup HTTP/1.1"),
        (ip, "GET /server-status HTTP/1.1"),
        (ip, "GET /phpinfo.php HTTP/1.1"),
        (ip, "GET /old HTTP/1.1"),
        (ip, "GET /dev HTTP/1.1"),
    ]


def endpoint_scan_sequence(ip):
    endpoints = [
        "/admin",
        "/login",
        "/api",
        "/test",
        "/debug",
        "/backup",
        "/config",
        "/old",
        "/dev",
        "/internal",
        "/staging",
        "/health",
    ]
    return [(ip, f"GET {endpoint} HTTP/1.1") for endpoint in endpoints]


# ============================================================
# Protocol encoder
# ============================================================


def encode_log_frame(ip, request):
    """Return the full binary frame for a single log."""
    ip_bytes = ip.encode("utf-8")
    req_bytes = request.encode("utf-8")
    # Payload: [IP len u8][IP][Request len u16][Request]
    payload = (
        bytes([len(ip_bytes)])
        + ip_bytes
        + struct.pack(">H", len(req_bytes))
        + req_bytes
    )
    # Type 0 = LOG
    body = b"\x00" + payload
    # Length prefix
    return struct.pack(">I", len(body)) + body


def encode_sequence(seq):
    """Convert a sequence of (ip, request) tuples into a list of frames."""
    return [encode_log_frame(ip, req) for ip, req in seq]


# ============================================================
# Pre-encoding all possible frames
# ============================================================

# Normal logs
normal_frames = []
for ip in NORMAL_IPS:
    for req in NORMAL_REQUESTS:
        normal_frames.append(encode_log_frame(ip, req))

# Threat logs
threat_frames = []

# SQLi
for pattern in SQLI:
    for ip in ATTACK_IPS:
        req = f"GET /login?user=admin{pattern} HTTP/1.1"
        threat_frames.append(encode_log_frame(ip, req))

# XSS
for pattern in XSS:
    for ip in ATTACK_IPS:
        req = f"GET /search?q={pattern} HTTP/1.1"
        threat_frames.append(encode_log_frame(ip, req))

# Path traversal
for pattern in PATH_TRAVERSAL:
    for ip in ATTACK_IPS:
        req = f"GET /download?file={pattern} HTTP/1.1"
        threat_frames.append(encode_log_frame(ip, req))

# Command injection
for pattern in COMMAND_INJECTION:
    for ip in ATTACK_IPS:
        req = f"GET /ping?host=127.0.0.1{pattern} HTTP/1.1"
        threat_frames.append(encode_log_frame(ip, req))

# Sensitive access
for path in SENSITIVE_ACCESS:
    for ip in ATTACK_IPS:
        req = f"GET {path} HTTP/1.1"
        threat_frames.append(encode_log_frame(ip, req))

# SSRF
for target in SSRF:
    for ip in ATTACK_IPS:
        req = f"GET /fetch?url=http://{target}:8080/admin HTTP/1.1"
        threat_frames.append(encode_log_frame(ip, req))

# LDAP
for pattern in LDAP_INJECTION:
    for ip in ATTACK_IPS:
        req = f"GET /users?name={pattern} HTTP/1.1"
        threat_frames.append(encode_log_frame(ip, req))

# XXE
for pattern in XXE:
    for ip in ATTACK_IPS:
        req = f"POST /xml HTTP/1.1 body={pattern}"
        threat_frames.append(encode_log_frame(ip, req))

# HTTP anomaly
http_anomalies = [
    "INVALID_METHOD /login",
    "GET /login",
    "GET / HTTP/9.9",
    "Content-Length: 100 Content-Length: 500",
    "Content-Length: -1",
    "OVERSIZED_REQUEST",
    "OVERSIZED_HEADER",
    "INVALID_HEADER",
    "Transfer-Encoding: invalid",
    "INVALID_CHUNKED_ENCODING",
]
for anomaly in http_anomalies:
    for ip in ATTACK_IPS:
        req = "HTTP_ANOMALY " + anomaly
        threat_frames.append(encode_log_frame(ip, req))

# Auth events (non-threat)
auth_events = []
for ip in NORMAL_IPS:
    auth_events.append(encode_log_frame(ip, "LOGIN_FAILED user=user"))
    auth_events.append(encode_log_frame(ip, "LOGIN_SUCCESS user=user"))
    auth_events.append(encode_log_frame(ip, "ADMIN_ACCESS /admin"))

# Non-threat pool (normal + auth)
non_threat_pool = normal_frames + auth_events
threat_pool = threat_frames

# Behavioral sequences (pre-encoded)
brute_force_sequences = [encode_sequence(brute_force_sequence(ip)) for ip in ATTACK_IPS]
credential_attack_sequences = [
    encode_sequence(credential_attack_sequence(ip)) for ip in ATTACK_IPS
]
account_compromise_sequences = [
    encode_sequence(account_compromise_sequence(ip)) for ip in ATTACK_IPS
]
multi_stage_sequences = [encode_sequence(multi_stage_sequence(ip)) for ip in ATTACK_IPS]
recon_sequences = [encode_sequence(recon_sequence(ip)) for ip in ATTACK_IPS]
endpoint_scan_sequences = [
    encode_sequence(endpoint_scan_sequence(ip)) for ip in ATTACK_IPS
]

# ============================================================
# Batch generation (optimized)
# ============================================================


def generate_batch(size):
    """Return bytes containing `size` concatenated frames."""
    frames = []

    # Occasionally insert a behavioral sequence
    r = random.random()
    if r < 0.002:
        seq = random.choice(brute_force_sequences)
        frames.extend(seq)
        size -= len(seq)
    elif r < 0.004:
        seq = random.choice(credential_attack_sequences)
        frames.extend(seq)
        size -= len(seq)
    elif r < 0.006:
        seq = random.choice(account_compromise_sequences)
        frames.extend(seq)
        size -= len(seq)
    elif r < 0.008:
        seq = random.choice(multi_stage_sequences)
        frames.extend(seq)
        size -= len(seq)
    elif r < 0.010:
        seq = random.choice(recon_sequences)
        frames.extend(seq)
        size -= len(seq)
    elif r < 0.012:
        seq = random.choice(endpoint_scan_sequences)
        frames.extend(seq)
        size -= len(seq)

    while size > 0:
        # 90% non-threat, 10% threat
        if random.random() < 0.90:
            frames.append(random.choice(non_threat_pool))
        else:
            frames.append(random.choice(threat_pool))
        size -= 1

    return b"".join(frames)


# ============================================================
# Sender
# ============================================================


def run(host, port, target_rate):
    print("FlareWatch Log Generator")
    print("========================")
    print(f"Destination : {host}:{port}")
    print(f"Target rate : {target_rate:,} logs/sec")
    print(f"Batch size  : {BATCH_SIZE:,}")
    print()

    print("Connecting...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    sock.connect((host, port))
    print("Connected.")
    print()

    sent_logs = 0
    start = time.perf_counter()
    last_report = start

    batches_per_second = target_rate / BATCH_SIZE
    batch_interval = 1.0 / batches_per_second
    next_send = time.perf_counter()

    try:
        while True:
            batch = generate_batch(BATCH_SIZE)
            sock.sendall(batch)
            sent_logs += BATCH_SIZE
            next_send += batch_interval

            now = time.perf_counter()
            if now - last_report >= 1.0:
                elapsed = now - start
                rate = sent_logs / elapsed
                print(
                    f"\rlogs={sent_logs:,} | rate={rate:,.0f}/sec | "
                    f"target={target_rate:,}/sec",
                    end="",
                    flush=True,
                )
                last_report = now

            sleep_time = next_send - time.perf_counter()
            if sleep_time > 0:
                time.sleep(sleep_time)
            elif time.perf_counter() - next_send > 1.0:
                next_send = time.perf_counter()

    except KeyboardInterrupt:
        elapsed = time.perf_counter() - start
        print("\n\nStopped.")
        if elapsed > 0:
            print(f"Total logs : {sent_logs:,}")
            print(f"Average    : {sent_logs / elapsed:,.0f} logs/sec")
    finally:
        sock.close()


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FlareWatch TCP log generator")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--rate", type=int, default=TARGET_RATE, help="Target logs/sec")
    args = parser.parse_args()
    run(args.host, args.port, args.rate)
