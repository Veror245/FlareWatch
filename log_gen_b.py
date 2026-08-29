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
# Normal traffic
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


def normal_log():
    ip = random.choice(NORMAL_IPS)
    request = random.choice(NORMAL_REQUESTS)
    return ip, request


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
# Individual threat logs
# ============================================================


def sqli_log():
    ip = random.choice(ATTACK_IPS)
    pattern = random.choice(SQLI)
    return ip, f"GET /login?user=admin{pattern} HTTP/1.1"


def xss_log():
    ip = random.choice(ATTACK_IPS)
    pattern = random.choice(XSS)
    return ip, f"GET /search?q={pattern} HTTP/1.1"


def path_traversal_log():
    ip = random.choice(ATTACK_IPS)
    pattern = random.choice(PATH_TRAVERSAL)
    return ip, f"GET /download?file={pattern} HTTP/1.1"


def command_injection_log():
    ip = random.choice(ATTACK_IPS)
    pattern = random.choice(COMMAND_INJECTION)
    return ip, f"GET /ping?host=127.0.0.1{pattern} HTTP/1.1"


def sensitive_access_log():
    ip = random.choice(ATTACK_IPS)
    path = random.choice(SENSITIVE_ACCESS)
    return ip, f"GET {path} HTTP/1.1"


def ssrf_log():
    ip = random.choice(ATTACK_IPS)
    target = random.choice(SSRF)
    return ip, f"GET /fetch?url=http://{target}:8080/admin HTTP/1.1"


def ldap_log():
    ip = random.choice(ATTACK_IPS)
    pattern = random.choice(LDAP_INJECTION)
    return ip, f"GET /users?name={pattern} HTTP/1.1"


def xxe_log():
    ip = random.choice(ATTACK_IPS)
    pattern = random.choice(XXE)
    return ip, f"POST /xml HTTP/1.1 body={pattern}"


def http_anomaly_log():
    ip = random.choice(ATTACK_IPS)

    anomalies = [
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

    return ip, "HTTP_ANOMALY " + random.choice(anomalies)


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
    users = [
        "admin",
        "root",
        "administrator",
        "test",
        "guest",
        "support",
        "user",
    ]

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
# Random LOG
# ============================================================

SIGNATURE_GENERATORS = [
    sqli_log,
    xss_log,
    path_traversal_log,
    command_injection_log,
    sensitive_access_log,
    ssrf_log,
    ldap_log,
    xxe_log,
    http_anomaly_log,
]


def random_log_event():
    r = random.random()

    # 90% normal
    if r < 0.90:
        return normal_log()

    # 5% authentication events
    if r < 0.95:
        ip = random.choice(NORMAL_IPS)

        return random.choice(
            [
                lambda: (ip, "LOGIN_FAILED user=user"),
                lambda: (ip, "LOGIN_SUCCESS user=user"),
                lambda: (ip, "ADMIN_ACCESS /admin"),
            ]
        )()

    # 5% individual threats
    return random.choice(SIGNATURE_GENERATORS)()


# ============================================================
# Random EVENT
#
# Event types:
#   0 = LOGIN_FAILED
#   1 = LOGIN_SUCCESS
#   2 = ADMIN_ACCESS
#   3 = SUSPICIOUS_ENDPOINT
#
# Threat type = 255 means NO_THREAT
# ============================================================


def random_event():
    ip = random.choice(ATTACK_IPS)
    event_type = random.randint(0, 3)

    if event_type == 0:
        request = "LOGIN_FAILED user=admin"

    elif event_type == 1:
        request = "LOGIN_SUCCESS user=admin"

    elif event_type == 2:
        request = "ADMIN_ACCESS /admin"

    else:
        endpoint = random.choice(
            [
                "/admin",
                "/.env",
                "/.git",
                "/config",
                "/debug",
                "/backup",
                "/server-status",
                "/phpinfo.php",
            ]
        )

        request = f"GET {endpoint} HTTP/1.1"

    return ip, request, event_type


# ============================================================
# Protocol encoders
# ============================================================


def encode_log(ip, request):
    """
    LOG:

        [4-byte length]
        [1-byte type = 0]
        [IP len u8]
        [IP]
        [Request len u16]
        [Request]
    """

    ip_bytes = ip.encode("utf-8")
    request_bytes = request.encode("utf-8")

    if len(ip_bytes) > 255:
        raise ValueError("IP exceeds u8 length")

    if len(request_bytes) > 65535:
        raise ValueError("Request exceeds u16 length")

    payload = (
        struct.pack(">B", len(ip_bytes))
        + ip_bytes
        + struct.pack(">H", len(request_bytes))
        + request_bytes
    )

    # Type 0 = LOG
    body = struct.pack(">B", 0) + payload

    return struct.pack(">I", len(body)) + body


def encode_event(ip, request, event_type, threat_type=255):
    """
    EVENT:

        [4-byte length]
        [1-byte type = 4]
        [Event type u8]
        [Threat type u8]
        [IP len u8]
        [IP]
        [Request len u16]
        [Request]
    """

    ip_bytes = ip.encode("utf-8")
    request_bytes = request.encode("utf-8")

    if len(ip_bytes) > 255:
        raise ValueError("IP exceeds u8 length")

    if len(request_bytes) > 65535:
        raise ValueError("Request exceeds u16 length")

    payload = (
        struct.pack(">B", event_type)
        + struct.pack(">B", threat_type)
        + struct.pack(">B", len(ip_bytes))
        + ip_bytes
        + struct.pack(">H", len(request_bytes))
        + request_bytes
    )

    # Type 4 = EVENT
    body = struct.pack(">B", 4) + payload

    return struct.pack(">I", len(body)) + body


# ============================================================
# Batch generation
# ============================================================


def generate_batch(size):
    frames = []

    for _ in range(size):
        # 80% LOG
        if random.random() < 0.80:
            ip, request = random_log_event()

            frames.append(encode_log(ip, request))

        # 20% EVENT
        else:
            ip, request, event_type = random_event()

            frames.append(
                encode_event(
                    ip,
                    request,
                    event_type,
                    threat_type=255,
                )
            )

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
    print("Distribution: 80% LOG / 20% EVENT")
    print()

    print("Connecting...")

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_SNDBUF,
        4 * 1024 * 1024,
    )

    sock.connect((host, port))

    print("Connected.")
    print()

    sent_messages = 0

    start = time.perf_counter()
    last_report = start

    batches_per_second = target_rate / BATCH_SIZE
    batch_interval = 1.0 / batches_per_second

    next_send = time.perf_counter()

    try:
        while True:
            batch = generate_batch(BATCH_SIZE)

            # One TCP write containing many protocol frames.
            sock.sendall(batch)

            sent_messages += BATCH_SIZE

            next_send += batch_interval

            now = time.perf_counter()

            if now - last_report >= 1.0:
                elapsed = now - start
                rate = sent_messages / elapsed

                print(
                    f"\r"
                    f"messages={sent_messages:,} | "
                    f"rate={rate:,.0f}/sec | "
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
            print(f"Total messages : {sent_messages:,}")
            print(f"Average        : {sent_messages / elapsed:,.0f} messages/sec")

    finally:
        sock.close()


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FlareWatch TCP log generator")

    parser.add_argument(
        "--host",
        default=HOST,
    )

    parser.add_argument(
        "--port",
        type=int,
        default=PORT,
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=TARGET_RATE,
        help="Target messages/sec",
    )

    args = parser.parse_args()

    run(
        args.host,
        args.port,
        args.rate,
    )
