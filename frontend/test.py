import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 4000

logs = [
    ("192.168.1.10", "GET /login?user=admin HTTP/1.1"),
    ("192.168.1.11", "GET /search?q=hello HTTP/1.1"),
    ("192.168.1.12", "GET /admin HTTP/1.1"),
    ("192.168.1.13", "GET /index.php?id=1' OR '1'='1 HTTP/1.1"),
    ("192.168.1.14", "GET /test?query=hello HTTP/1.1"),
]

with socket.create_connection((HOST, PORT)) as sock:
    for ip, request in logs:
        ip_bytes = ip.encode()
        request_bytes = request.encode()

        payload = (
            bytes([0]) +
            bytes([len(ip_bytes)]) +
            ip_bytes +
            struct.pack(">H", len(request_bytes)) +
            request_bytes
        )

        sock.sendall(struct.pack(">I", len(payload)))
        sock.sendall(payload)

        print("Sent:", request)
        time.sleep(0.5)