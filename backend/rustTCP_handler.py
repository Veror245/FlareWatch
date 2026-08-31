"""
FlareWatch merged backend.

Architecture
------------
Browser <-> WebSocket :4005 <-> Python

Python -> Rust :4000
    Rust listens on 4000. Python connects and sends SEARCH requests.

Rust -> Python :4002
    Python listens on 4002. Rust connects and sends protocol messages.

Dev 2 -> Python :4004
    Python listens on 4004. Dev 2 sends generated big-event incidents.

Only Python standard-library modules are used.
"""

import socket
import struct
import json
import threading
import hashlib
import base64
import queue
import re


# ============================================================
# CONFIGURATION
# ============================================================

RUST_HOST = "127.0.0.1"
RUST_REQUEST_PORT = 4000

RUST_RESPONSE_HOST = "0.0.0.0"
RUST_RESPONSE_PORT = 4002

DEV2_HOST = "127.0.0.1"
DEV2_PORT = 4004

WEBSOCKET_HOST = "0.0.0.0"
WEBSOCKET_PORT = 4005

MAX_MESSAGE_SIZE = 1024 * 1024


# ============================================================
# FLAREWATCH MESSAGE TYPES
# ============================================================

TYPE_LOG = 0
TYPE_THREAT = 1
TYPE_NOTHREAT = 2
TYPE_STATS = 3
TYPE_EVENT = 4
TYPE_SEARCH = 5

MESSAGE_TYPE_THREAT = TYPE_THREAT


# ============================================================
# THREAT TYPES
# ============================================================

THREAT_TYPES = {
    0: "SQLI",
    1: "XSS",
    2: "PATH_TRAVERSAL",
    3: "COMMAND_INJECTION",
    4: "SENSITIVE_ACCESS",
    5: "SSRF",
    6: "LDAP_INJECTION",
    7: "XXE",
    8: "HTTP_ANOMALY",
    9: "BRUTE_FORCE",
    10: "CREDENTIAL_ATTACK",
    11: "RECON",
    12: "ENDPOINT_SCAN",
    13: "REQUEST_FLOOD",
    14: "ACCOUNT_COMPROMISE",
    15: "MULTI_STAGE_ATTACK",
    16: "ANOMALY",
}

OUTBOUND_THREATS = {
    9: "BRUTE_FORCE",
    10: "CREDENTIAL_ATTACK",
    11: "RECON",
    12: "ENDPOINT_SCAN",
    13: "REQUEST_FLOOD",
    14: "ACCOUNT_COMPROMISE",
    15: "MULTI_STAGE_ATTACK",
    16: "ANOMALY",
}


class ProtocolError(Exception):
    pass


# ============================================================
# GLOBAL STATE
# ============================================================

# Python -> Rust :4000
rust_request_socket = None
rust_request_lock = threading.Lock()
rust_request_connected = threading.Event()

# Rust -> Python :4002
rust_response_sockets = set()
rust_response_socket_lock = threading.Lock()

# SEARCH response coordination.
# The current SEARCH protocol has no request/correlation ID, so
# only one SEARCH transaction is allowed at a time.
search_lock = threading.Lock()
search_response_queue = queue.Queue()

# Browser clients.
websocket_clients = set()
websocket_clients_lock = threading.Lock()
websocket_send_locks = {}


# ============================================================
# TCP HELPER
# ============================================================

def recv_exact(sock, size):
    """Receive exactly `size` bytes from a TCP stream."""

    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            if len(data) == 0:
                return None

            raise ConnectionError(
                "Connection closed before receiving "
                "the complete message"
            )

        data.extend(chunk)

    return bytes(data)


# ============================================================
# PROTOCOL READ HELPERS
# ============================================================

def read_u8(data, offset):
    if offset + 1 > len(data):
        raise ProtocolError("Not enough data to read u8")

    return data[offset], offset + 1


def read_u16(data, offset):
    if offset + 2 > len(data):
        raise ProtocolError("Not enough data to read u16")

    value = struct.unpack_from(">H", data, offset)[0]
    return value, offset + 2


def read_u32(data, offset):
    if offset + 4 > len(data):
        raise ProtocolError("Not enough data to read u32")

    value = struct.unpack_from(">I", data, offset)[0]
    return value, offset + 4


def read_u64(data, offset):
    if offset + 8 > len(data):
        raise ProtocolError("Not enough data to read u64")

    value = struct.unpack_from(">Q", data, offset)[0]
    return value, offset + 8


def read_string_u8(data, offset):
    length, offset = read_u8(data, offset)
    end = offset + length

    if end > len(data):
        raise ProtocolError(
            "String extends beyond message boundary"
        )

    try:
        value = data[offset:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError(
            "Invalid UTF-8 string"
        ) from error

    return value, end


def read_string_u16(data, offset):
    length, offset = read_u16(data, offset)
    end = offset + length

    if end > len(data):
        raise ProtocolError(
            "String extends beyond message boundary"
        )

    try:
        value = data[offset:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError(
            "Invalid UTF-8 string"
        ) from error

    return value, end


# ============================================================
# RUST PROTOCOL PARSERS
# ============================================================

def parse_log(payload):
    offset = 0

    ip, offset = read_string_u8(payload, offset)
    request, offset = read_string_u16(payload, offset)

    if offset != len(payload):
        raise ProtocolError(
            "Extra bytes in LOG message"
        )

    return {
        "type": "log",
        "ip": ip,
        "request": request,
    }


def parse_threat(payload):
    offset = 0

    threat_type, offset = read_u8(
        payload,
        offset,
    )

    threat_name = THREAT_TYPES.get(
        threat_type,
        f"UNKNOWN_{threat_type}",
    )

    ip, offset = read_string_u8(
        payload,
        offset,
    )

    request, offset = read_string_u16(
        payload,
        offset,
    )

    if offset != len(payload):
        raise ProtocolError(
            "Extra bytes in THREAT message"
        )

    return {
        "type": "threat",
        "threat_type": threat_type,
        "threat_name": threat_name,
        "ip": ip,
        "request": request,
    }


def parse_nothreat(payload):
    offset = 0

    ip, offset = read_string_u8(
        payload,
        offset,
    )

    request, offset = read_string_u16(
        payload,
        offset,
    )

    if offset != len(payload):
        raise ProtocolError(
            "Extra bytes in NOTHREAT message"
        )

    return {
        "type": "nothreat",
        "ip": ip,
        "request": request,
    }


def parse_stats(payload):
    EXPECTED_SIZE = 20

    if len(payload) != EXPECTED_SIZE:
        raise ProtocolError(
            f"Invalid STATS size. Expected "
            f"{EXPECTED_SIZE}, got {len(payload)}"
        )

    offset = 0

    logs_processed, offset = read_u64(
        payload,
        offset,
    )

    threats_detected, offset = read_u64(
        payload,
        offset,
    )

    logs_per_second, offset = read_u32(
        payload,
        offset,
    )

    return {
        "type": "stats",
        "logs_processed": logs_processed,
        "threats_detected": threats_detected,
        "logs_per_second": logs_per_second,
    }


def parse_event(payload):
    """
    EVENT:

        [Event type u8][IP len u8][IP]
        [Request len u16][Request]
    """

    offset = 0

    event_type, offset = read_u8(
        payload,
        offset,
    )

    ip, offset = read_string_u8(
        payload,
        offset,
    )

    request, offset = read_string_u16(
        payload,
        offset,
    )

    if offset != len(payload):
        raise ProtocolError(
            "Extra bytes in EVENT message"
        )

    return {
        "type": "event",
        "event_type": event_type,
        "ip": ip,
        "request": request,
    }


def parse_search_response(payload):
    """
    SEARCH RESPONSE:

        [TIMESTAMP][THREAT][IP][REQ]

    One record per line.

    Example:

        [1725000000][SQLI][127.0.0.1][SELECT ...]
        [1725000001][XSS][10.0.0.5][<script>...]
    """

    text = payload.decode(
        "utf-8",
        errors="replace",
    )

    results = []

    # Timestamp and threat are bracketed; IP is a whitespace-delimited
    # field; the rest of the line belongs to the request.
    pattern = re.compile(
        r"^\[([^\]]*)\]\s+\[([^\]]*)\]\s+(\S+)"
        r"(?:\s+(.*))?$"
    )

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        line = line.strip()

        if not line:
            continue

        match = pattern.match(line)

        if not match:
            raise ProtocolError(
                f"Invalid SEARCH record at line "
                f"{line_number}: {line!r}"
            )

        timestamp_text, threat, ip, request = (
            match.groups()
        )

        try:
            timestamp = int(timestamp_text)
        except ValueError:
            timestamp = timestamp_text

        results.append({
            "timestamp": timestamp,
            "threat": threat,
            "ip": ip,
            "request": request or "",
        })

    return results


def parse_rust_message(message):
    """
    Parse a complete Rust message after the 4-byte length:

        [1-byte type][payload]
    """

    if len(message) < 1:
        raise ProtocolError(
            "Message does not contain a type byte"
        )

    message_type = message[0]
    payload = message[1:]

    if message_type == TYPE_LOG:
        return parse_log(payload)

    if message_type == TYPE_THREAT:
        return parse_threat(payload)

    if message_type == TYPE_NOTHREAT:
        return parse_nothreat(payload)

    if message_type == TYPE_STATS:
        return parse_stats(payload)

    if message_type == TYPE_EVENT:
        return parse_event(payload)

    if message_type == TYPE_SEARCH:
        results = parse_search_response(payload)

        return {
            "type": "search_response",
            "message_type": TYPE_SEARCH,
            "count": len(results),
            "results": results,
        }

    raise ProtocolError(
        f"Unknown message type: {message_type}"
    )


# ============================================================
# PYTHON -> RUST :4000
# ============================================================

def connect_to_rust():
    """
    Rust is the TCP server on :4000.
    Python connects to it.
    """

    global rust_request_socket

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(5)

    print(
        f"[RUST:4000] Connecting to "
        f"{RUST_HOST}:{RUST_REQUEST_PORT}..."
    )

    sock.connect(
        (
            RUST_HOST,
            RUST_REQUEST_PORT,
        )
    )

    sock.settimeout(None)

    with rust_request_lock:
        old_socket = rust_request_socket
        rust_request_socket = sock

    if old_socket is not None:
        try:
            old_socket.close()
        except OSError:
            pass

    rust_request_connected.set()

    print("[RUST:4000] Connected to Rust")


def send_to_rust(data):
    """Send one complete framed request to Rust :4000."""

    global rust_request_socket

    if not rust_request_connected.is_set():
        connect_to_rust()

    with rust_request_lock:
        sock = rust_request_socket

        if sock is None:
            raise ConnectionError(
                "Rust request socket is unavailable"
            )

        try:
            sock.sendall(data)

        except (
            BrokenPipeError,
            ConnectionResetError,
            OSError,
        ) as error:

            rust_request_connected.clear()

            try:
                sock.close()
            except OSError:
                pass

            rust_request_socket = None

            raise ConnectionError(
                "Rust request connection was lost"
            ) from error


# ============================================================
# RUST -> PYTHON :4002
# ============================================================

def start_rust_response_server():
    """
    Python listens on :4002.
    Rust connects here and sends responses/events.
    """

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    server.bind(
        (
            RUST_RESPONSE_HOST,
            RUST_RESPONSE_PORT,
        )
    )

    server.listen(5)

    print(
        f"[RUST:4002] Listening for Rust "
        f"responses on "
        f"{RUST_RESPONSE_HOST}:{RUST_RESPONSE_PORT}"
    )

    while True:
        conn, addr = server.accept()

        print(
            f"[RUST:4002] Rust connected from {addr}"
        )

        with rust_response_socket_lock:
            rust_response_sockets.add(conn)

        thread = threading.Thread(
            target=handle_rust_response_connection,
            args=(conn, addr),
            daemon=True,
        )

        thread.start()


def handle_rust_response_connection(
    conn,
    addr,
):
    """
    Read framed Rust messages:

        [4-byte length][1-byte type][payload]

    SEARCH responses are routed to search_response_queue.
    All other messages are parsed and broadcast to browsers.
    """

    try:
        while True:
            length_bytes = recv_exact(
                conn,
                4,
            )

            if length_bytes is None:
                break

            message_length = struct.unpack(
                ">I",
                length_bytes,
            )[0]

            if (
                message_length < 1
                or message_length > MAX_MESSAGE_SIZE
            ):
                raise ProtocolError(
                    f"Invalid Rust message length: "
                    f"{message_length}"
                )

            message = recv_exact(
                conn,
                message_length,
            )

            if message is None:
                break

            message_type = message[0]
            payload = message[1:]

            if message_type == TYPE_SEARCH:
                results = parse_search_response(
                    payload
                )

                search_response_queue.put({
                    "type": "search_response",
                    "message_type": TYPE_SEARCH,
                    "count": len(results),
                    "results": results,
                })

                continue

            event = parse_rust_message(
                message
            )

            print(
                "[RUST:4002] Parsed:"
            )
            print(
                json.dumps(
                    event,
                    indent=4,
                )
            )

            broadcast_json(event)

    except (
        ConnectionError,
        ConnectionResetError,
        OSError,
        ProtocolError,
    ) as error:

        print(
            f"[RUST:4002] Connection ended from "
            f"{addr}: {error}"
        )

    finally:
        with rust_response_socket_lock:
            rust_response_sockets.discard(conn)

        try:
            conn.close()
        except OSError:
            pass


# ============================================================
# SEARCH REQUEST / RESPONSE
# ============================================================

def build_search_message(request):
    """
    Build Rust SEARCH:

        [4-byte length]
        [1-byte type = 5]
        [2-byte request length]
        [UTF-8 request]
    """

    request_bytes = request.encode(
        "utf-8"
    )

    if len(request_bytes) > 65535:
        raise ProtocolError(
            "Search request is too long"
        )

    payload = (
        struct.pack(
            ">H",
            len(request_bytes),
        )
        + request_bytes
    )

    message_length = 1 + len(payload)

    return (
        struct.pack(
            ">I",
            message_length,
        )
        + bytes([TYPE_SEARCH])
        + payload
    )


def search_rust(request):
    """
    Send SEARCH to Rust :4000 and wait for its SEARCH
    response on Rust -> Python :4002.

    No correlation ID exists in the protocol, so SEARCH
    requests are serialized.
    """

    with search_lock:

        # Clear stale responses.
        while True:
            try:
                search_response_queue.get_nowait()
            except queue.Empty:
                break

        frame = build_search_message(
            request
        )

        send_to_rust(frame)

        print(
            f"[SEARCH] Sent to Rust: {request!r}"
        )

        try:
            result = search_response_queue.get(
                timeout=30
            )
        except queue.Empty as error:
            raise TimeoutError(
                "Timed out waiting for Rust SEARCH "
                "response on port 4002"
            ) from error

        result["query"] = request

        return result


# ============================================================
# DEV 2 -> PYTHON :4004
# ============================================================

def parse_incident(payload):
    """
    Dev2 incident payload:

        [Threat ID u8]
        [IP Length u8]
        [IP]
        [Details Length u16]
        [Details]
    """

    offset = 0

    threat_id, offset = read_u8(
        payload,
        offset,
    )

    threat_name = OUTBOUND_THREATS.get(
        threat_id,
        f"UNKNOWN_THREAT_{threat_id}",
    )

    ip, offset = read_string_u8(
        payload,
        offset,
    )

    details, offset = read_string_u16(
        payload,
        offset,
    )

    if offset != len(payload):
        raise ProtocolError(
            f"Unexpected {len(payload) - offset} "
            f"extra bytes in incident"
        )

    return {
        "type": "big_event",
        "message_type": MESSAGE_TYPE_THREAT,
        "threat_id": threat_id,
        "threat_name": threat_name,
        "ip": ip,
        "details": details,
    }


def handle_dev2_client(conn, addr):
    print(
        f"[DEV2:4004] Connected from {addr}"
    )

    try:
        while True:
            length_bytes = recv_exact(
                conn,
                4,
            )

            if length_bytes is None:
                break

            message_length = struct.unpack(
                ">I",
                length_bytes,
            )[0]

            if (
                message_length < 1
                or message_length > MAX_MESSAGE_SIZE
            ):
                raise ProtocolError(
                    "Invalid Dev2 message length"
                )

            type_bytes = recv_exact(
                conn,
                1,
            )

            if type_bytes is None:
                break

            message_type = type_bytes[0]

            payload = recv_exact(
                conn,
                message_length - 1,
            )

            if payload is None:
                break

            if message_type != MESSAGE_TYPE_THREAT:
                print(
                    f"[DEV2:4004] Ignoring message "
                    f"type: {message_type}"
                )
                continue

            event = parse_incident(
                payload
            )

            print(
                "\n[DEV2 -> MERGED SERVER] "
                "Incident received:"
            )

            print(
                json.dumps(
                    event,
                    indent=4,
                )
            )

            broadcast_json(event)

    except (
        ValueError,
        ConnectionError,
        OSError,
        ProtocolError,
    ) as error:

        print(
            f"[DEV2:4004] Error: {error}"
        )

    finally:
        try:
            conn.close()
        except OSError:
            pass

        print(
            f"[DEV2:4004] Disconnected: {addr}"
        )


def start_dev2_server():
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    server.bind(
        (
            DEV2_HOST,
            DEV2_PORT,
        )
    )

    server.listen(5)

    print(
        f"[DEV2:4004] Waiting for Dev 2 on "
        f"{DEV2_HOST}:{DEV2_PORT}"
    )

    while True:
        conn, addr = server.accept()

        thread = threading.Thread(
            target=handle_dev2_client,
            args=(conn, addr),
            daemon=True,
        )

        thread.start()


# ============================================================
# WEBSOCKET HANDSHAKE
# ============================================================

def perform_websocket_handshake(
    client_socket,
):
    request = b""

    while b"\r\n\r\n" not in request:
        chunk = client_socket.recv(4096)

        if not chunk:
            raise ConnectionError(
                "Browser disconnected during handshake"
            )

        request += chunk

        if len(request) > 16384:
            raise ProtocolError(
                "WebSocket handshake too large"
            )

    request_text = request.decode(
        "utf-8"
    )

    headers = {}

    for line in request_text.split(
        "\r\n"
    )[1:]:

        if ":" not in line:
            continue

        name, value = line.split(
            ":",
            1,
        )

        headers[
            name.strip().lower()
        ] = value.strip()

    if headers.get(
        "upgrade",
        "",
    ).lower() != "websocket":

        raise ProtocolError(
            "Missing WebSocket Upgrade header"
        )

    websocket_key = headers.get(
        "sec-websocket-key"
    )

    if websocket_key is None:
        raise ProtocolError(
            "Missing Sec-WebSocket-Key"
        )

    websocket_guid = (
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    )

    accept_hash = hashlib.sha1(
        (
            websocket_key
            + websocket_guid
        ).encode("utf-8")
    ).digest()

    accept_key = base64.b64encode(
        accept_hash
    ).decode("utf-8")

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )

    client_socket.sendall(
        response.encode("utf-8")
    )


# ============================================================
# WEBSOCKET FRAMES
# ============================================================

def send_websocket_frame(
    client_socket,
    payload,
    opcode=0x1,
):
    if isinstance(payload, str):
        payload = payload.encode(
            "utf-8"
        )

    first_byte = 0x80 | opcode
    payload_length = len(payload)

    if payload_length <= 125:

        header = struct.pack(
            "!BB",
            first_byte,
            payload_length,
        )

    elif payload_length <= 65535:

        header = struct.pack(
            "!BBH",
            first_byte,
            126,
            payload_length,
        )

    else:

        header = struct.pack(
            "!BBQ",
            first_byte,
            127,
            payload_length,
        )

    client_socket.sendall(
        header + payload
    )


def receive_websocket_frame(
    client_socket,
):
    header = recv_exact(
        client_socket,
        2,
    )

    if header is None:
        return None

    first_byte = header[0]
    second_byte = header[1]

    fin = (
        first_byte & 0x80
    ) != 0

    opcode = (
        first_byte & 0x0F
    )

    masked = (
        second_byte & 0x80
    ) != 0

    payload_length = (
        second_byte & 0x7F
    )

    if payload_length == 126:

        length_bytes = recv_exact(
            client_socket,
            2,
        )

        if length_bytes is None:
            raise ConnectionError(
                "Incomplete WebSocket length"
            )

        payload_length = struct.unpack(
            "!H",
            length_bytes,
        )[0]

    elif payload_length == 127:

        length_bytes = recv_exact(
            client_socket,
            8,
        )

        if length_bytes is None:
            raise ConnectionError(
                "Incomplete WebSocket length"
            )

        payload_length = struct.unpack(
            "!Q",
            length_bytes,
        )[0]

    if payload_length > MAX_MESSAGE_SIZE:
        raise ProtocolError(
            "WebSocket payload too large"
        )

    if not masked:
        raise ProtocolError(
            "Browser WebSocket frame was not masked"
        )

    masking_key = recv_exact(
        client_socket,
        4,
    )

    if masking_key is None:
        raise ConnectionError(
            "Incomplete WebSocket masking key"
        )

    masked_payload = recv_exact(
        client_socket,
        payload_length,
    )

    if masked_payload is None:
        raise ConnectionError(
            "Incomplete WebSocket payload"
        )

    payload = bytearray(
        payload_length
    )

    for i in range(payload_length):
        payload[i] = (
            masked_payload[i]
            ^ masking_key[i % 4]
        )

    return {
        "fin": fin,
        "opcode": opcode,
        "payload": bytes(payload),
    }


# ============================================================
# WEBSOCKET JSON
# ============================================================

def send_json_websocket(
    client_socket,
    data,
):
    message = json.dumps(
        data,
        ensure_ascii=False,
    )

    with websocket_clients_lock:
        send_lock = websocket_send_locks.get(
            client_socket
        )

    if send_lock is None:
        send_websocket_frame(
            client_socket,
            message,
        )
        return

    with send_lock:
        send_websocket_frame(
            client_socket,
            message,
        )


def broadcast_json(data):
    """
    Send one structured JSON message to every connected browser.

    Both Rust messages and Dev2 incidents use this function.
    """

    message = json.dumps(
        data,
        ensure_ascii=False,
    )

    with websocket_clients_lock:
        clients = list(
            websocket_clients
        )

    dead_clients = []

    for client in clients:

        try:
            with websocket_clients_lock:
                send_lock = websocket_send_locks.get(
                    client
                )

            if send_lock is None:
                send_websocket_frame(
                    client,
                    message,
                )
            else:
                with send_lock:
                    send_websocket_frame(
                        client,
                        message,
                    )

        except OSError:
            dead_clients.append(
                client
            )

    if dead_clients:
        with websocket_clients_lock:
            for client in dead_clients:
                websocket_clients.discard(
                    client
                )
                websocket_send_locks.pop(
                    client,
                    None,
                )


# ============================================================
# BROWSER MESSAGE HANDLING
# ============================================================

def handle_browser_json(
    client_socket,
    data,
):
    """
    Browser application protocol.

    SEARCH:

        {
            "type": 5,
            "request": "error"
        }

    The SEARCH is sent to Rust :4000. Rust's response arrives
    on Python :4002 and is returned on this same WebSocket.
    """

    message_type = data.get(
        "type"
    )

    if message_type == TYPE_SEARCH:

        request = data.get(
            "request"
        )

        if not isinstance(
            request,
            str,
        ):

            send_json_websocket(
                client_socket,
                {
                    "type": "error",
                    "error": (
                        "SEARCH request must contain "
                        "a string 'request'"
                    ),
                },
            )

            return

        try:

            result = search_rust(
                request
            )

            send_json_websocket(
                client_socket,
                result
            )

        except (
            ConnectionError,
            TimeoutError,
            ProtocolError,
            OSError,
        ) as error:

            send_json_websocket(
                client_socket,
                {
                    "type": "search_response",
                    "message_type": TYPE_SEARCH,
                    "query": request,
                    "count": 0,
                    "results": [],
                    "error": str(error),
                },
            )

        return

    send_json_websocket(
        client_socket,
        {
            "type": "error",
            "error": (
                f"Unsupported message type: "
                f"{message_type}"
            ),
        },
    )


def handle_websocket_client(
    client_socket,
    client_address,
):
    print(
        f"[WS] Browser connecting: "
        f"{client_address}"
    )

    try:

        perform_websocket_handshake(
            client_socket
        )

        with websocket_clients_lock:
            websocket_clients.add(
                client_socket
            )
            websocket_send_locks[
                client_socket
            ] = threading.Lock()

        print(
            f"[WS] Browser connected: "
            f"{client_address}"
        )

        send_json_websocket(
            client_socket,
            {
                "type": "connection",
                "status": "connected",
                "message": (
                    "Connected to FlareWatch backend"
                ),
            },
        )

        while True:

            frame = receive_websocket_frame(
                client_socket
            )

            if frame is None:
                break

            opcode = frame[
                "opcode"
            ]

            if opcode == 0x1:

                try:

                    text = frame[
                        "payload"
                    ].decode("utf-8")

                    data = json.loads(
                        text
                    )

                except UnicodeDecodeError:

                    send_json_websocket(
                        client_socket,
                        {
                            "type": "error",
                            "error": (
                                "Invalid UTF-8 "
                                "WebSocket payload"
                            ),
                        },
                    )

                    continue

                except json.JSONDecodeError as error:

                    send_json_websocket(
                        client_socket,
                        {
                            "type": "error",
                            "error": (
                                f"Invalid JSON: {error}"
                            ),
                        },
                    )

                    continue

                print(
                    f"[WS] Browser message: "
                    f"{text}"
                )

                handle_browser_json(
                    client_socket,
                    data,
                )

            elif opcode == 0x8:

                send_websocket_frame(
                    client_socket,
                    b"",
                    opcode=0x8,
                )

                break

            elif opcode == 0x9:

                send_websocket_frame(
                    client_socket,
                    frame["payload"],
                    opcode=0xA,
                )

            elif opcode == 0xA:
                pass

            else:

                print(
                    f"[WS] Unsupported opcode: "
                    f"{opcode}"
                )

    except (
        ProtocolError,
        ConnectionError,
        OSError,
        ValueError,
    ) as error:

        print(
            f"[WS] Error from "
            f"{client_address}: {error}"
        )

    finally:

        with websocket_clients_lock:

            websocket_clients.discard(
                client_socket
            )

            websocket_send_locks.pop(
                client_socket,
                None,
            )

        try:
            client_socket.close()
        except OSError:
            pass

        print(
            f"[WS] Browser disconnected: "
            f"{client_address}"
        )


# ============================================================
# WEBSOCKET SERVER :4005
# ============================================================

def start_websocket_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    server.bind(
        (
            WEBSOCKET_HOST,
            WEBSOCKET_PORT,
        )
    )

    server.listen(5)

    print(
        f"[WS] WebSocket server listening "
        f"on ws://localhost:{WEBSOCKET_PORT}"
    )

    while True:

        client_socket, client_address = (
            server.accept()
        )

        thread = threading.Thread(
            target=handle_websocket_client,
            args=(
                client_socket,
                client_address,
            ),
            daemon=True,
        )

        thread.start()


# ============================================================
# MAIN
# ============================================================

def main():

    # 1. Python must listen on :4002 before Rust connects.
    rust_response_thread = threading.Thread(
        target=start_rust_response_server,
        daemon=True,
    )

    rust_response_thread.start()


    # 2. Python listens on :4004 for Dev2.
    dev2_thread = threading.Thread(
        target=start_dev2_server,
        daemon=True,
    )

    dev2_thread.start()


    # 3. Python connects to Rust's :4000.
    try:

        connect_to_rust()

    except OSError as error:

        print(
            f"[RUST:4000] Initial connection failed: "
            f"{error}"
        )

        print(
            "[RUST:4000] :4002, :4004 and WebSocket "
            "listeners will continue running."
        )


    # 4. Browser connects to :4005.
    start_websocket_server()


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print(
            "\n[SERVER] Shutting down..."
        )