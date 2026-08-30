"""
FlareWatch Backend
==================

ARCHITECTURE FOR SEARCH + LIVE TELEMETRY

Browser
   |
   | WebSocket :4005
   v
Python Backend
   |
   | TCP :4000
   v
Rust TCP Server

SEARCH:
Browser -> Python -> Rust -> Python -> same Browser WebSocket

LIVE RUST EVENTS:
Rust -> Python -> all connected Browser WebSockets

The browser remains a WebSocket client. Python is the only
component that talks to the browser over WebSocket.

Only Python standard-library modules are used.
"""



# ============================================================
# IMPORTS
# ============================================================

import socket
import struct
import threading
import json
import hashlib
import base64
import time
import queue


# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# Rust TCP SERVER
#
# Python connects TO Rust on port 4000.
# Rust is the TCP server.
# ------------------------------------------------------------

RUST_HOST = "127.0.0.1"
RUST_REQUEST_PORT = 4000
RUST_RESPONSE_HOST = "0.0.0.0"
RUST_RESPONSE_PORT = 4002


# ------------------------------------------------------------
# Browser WebSocket server
#
# Keep the existing project WebSocket port: 4003.
# ------------------------------------------------------------

WS_HOST = "0.0.0.0"
WS_PORT = 4003


# ------------------------------------------------------------
# Maximum Rust IPC message size
# ------------------------------------------------------------

MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB


# ============================================================
# FLAREWATCH MESSAGE TYPES
# ============================================================

TYPE_LOG = 0
TYPE_THREAT = 1
TYPE_NOTHREAT = 2
TYPE_STATS = 3
TYPE_EVENT = 4
TYPE_SEARCH = 5


# ------------------------------------------------------------
# Rust connection state
# ------------------------------------------------------------

rust_request_socket = None
rust_request_lock = threading.Lock()
rust_request_connected = threading.Event()

rust_response_socket = set()
rust_response_socket_lock = threading.Lock()
rust_response_connected = threading.Event()


# ------------------------------------------------------------
# SEARCH response coordination
#
# The current protocol has no request-id field, so only one
# SEARCH request may be in flight at a time.
# ------------------------------------------------------------

search_lock = threading.Lock()
search_response_queue = queue.Queue()


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
}

# ============================================================
# PROTOCOL EXCEPTION
# ============================================================

class ProtocolError(Exception):
    """
    Raised when data received from Rust does not follow
    the FlareWatch binary protocol.
    """

    pass


# ============================================================
# GLOBAL WEBSOCKET CLIENT STORAGE
# ============================================================

"""
Every connected browser WebSocket is stored here.

Example:

    websocket_clients = {
        browser_socket_1,
        browser_socket_2,
        browser_socket_3
    }

We protect this set using websocket_clients_lock because
multiple threads may access it.
"""

websocket_clients = set()

websocket_clients_lock = threading.Lock()


# ============================================================
# TCP: RECEIVE EXACTLY N BYTES
# ============================================================

def recv_exact(sock, size):
    """
    Receive exactly `size` bytes from a TCP socket.

    TCP is a STREAM, not a message-based protocol.

    Therefore:

        sock.recv(100)

    does NOT guarantee that exactly 100 bytes will arrive.

    We keep receiving until we have exactly the requested
    number of bytes.

    Parameters
    ----------
    sock:
        Connected socket.

    size:
        Number of bytes required.

    Returns
    -------
    bytes
        Exactly `size` bytes.

    None
        If the peer closed the connection before sending
        any bytes.
    """

    data = bytearray()

    while len(data) < size:

        remaining = size - len(data)

        chunk = sock.recv(remaining)

        # Empty bytes means connection closed.
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
# PROTOCOL: READ u8
# ============================================================

def read_u8(data, offset):
    """
    Read an unsigned 8-bit integer.

    u8 = 1 byte.
    """

    if offset + 1 > len(data):

        raise ProtocolError(
            "Not enough data to read u8"
        )

    value = data[offset]

    return value, offset + 1


# ============================================================
# PROTOCOL: READ u16
# ============================================================

def read_u16(data, offset):
    """
    Read an unsigned 16-bit integer.

    u16 = 2 bytes.

    BIG-ENDIAN.
    """

    if offset + 2 > len(data):

        raise ProtocolError(
            "Not enough data to read u16"
        )

    value = struct.unpack_from(
        ">H",
        data,
        offset
    )[0]

    return value, offset + 2


# ============================================================
# PROTOCOL: READ u32
# ============================================================

def read_u32(data, offset):
    """
    Read an unsigned 32-bit integer.

    u32 = 4 bytes.

    BIG-ENDIAN.
    """

    if offset + 4 > len(data):

        raise ProtocolError(
            "Not enough data to read u32"
        )

    value = struct.unpack_from(
        ">I",
        data,
        offset
    )[0]

    return value, offset + 4


# ============================================================
# PROTOCOL: READ u64
# ============================================================

def read_u64(data, offset):
    """
    Read an unsigned 64-bit integer.

    u64 = 8 bytes.

    BIG-ENDIAN.
    """

    if offset + 8 > len(data):

        raise ProtocolError(
            "Not enough data to read u64"
        )

    value = struct.unpack_from(
        ">Q",
        data,
        offset
    )[0]

    return value, offset + 8


# ============================================================
# PROTOCOL: READ u8-LENGTH STRING
# ============================================================

def read_string_u8(data, offset):
    """
    Read:

        [length u8][UTF-8 string]

    Used for IP addresses.
    """

    # Read string length.
    length, offset = read_u8(
        data,
        offset
    )

    # Calculate string end.
    end = offset + length

    if end > len(data):

        raise ProtocolError(
            "String extends beyond message boundary"
        )

    # Extract bytes.
    string_bytes = data[offset:end]

    # Convert UTF-8 bytes -> Python str.
    try:

        value = string_bytes.decode("utf-8")

    except UnicodeDecodeError as error:

        raise ProtocolError(
            "Invalid UTF-8 string"
        ) from error

    return value, end


# ============================================================
# PROTOCOL: READ u16-LENGTH STRING
# ============================================================

def read_string_u16(data, offset):
    """
    Read:

        [length u16][UTF-8 string]

    Used for request strings.
    """

    # Read string length.
    length, offset = read_u16(
        data,
        offset
    )

    # Calculate end.
    end = offset + length

    if end > len(data):

        raise ProtocolError(
            "String extends beyond message boundary"
        )

    # Extract bytes.
    string_bytes = data[offset:end]

    # Decode UTF-8.
    try:

        value = string_bytes.decode("utf-8")

    except UnicodeDecodeError as error:

        raise ProtocolError(
            "Invalid UTF-8 string"
        ) from error

    return value, end


# ============================================================
# PARSE LOG
# ============================================================

def parse_log(payload):
    """
    LOG payload:

        [IP len u8]
        [IP]
        [REQ len u16]
        [REQ]
    """

    offset = 0

    ip, offset = read_string_u8(
        payload,
        offset
    )

    request, offset = read_string_u16(
        payload,
        offset
    )

    if offset != len(payload):

        raise ProtocolError(
            "Extra bytes in LOG message"
        )

    return {
        "type": "log",
        "ip": ip,
        "request": request
    }


# ============================================================
# PARSE THREAT
# ============================================================

def parse_threat(payload):
    """
    THREAT payload:

        [Threat type u8]
        [IP len u8]
        [IP]
        [REQ len u16]
        [REQ]
    """

    offset = 0

    # Threat ID.
    threat_type, offset = read_u8(
        payload,
        offset
    )

    # Human-readable name.
    threat_name = THREAT_TYPES.get(
        threat_type,
        f"UNKNOWN_{threat_type}"
    )

    # IP address.
    ip, offset = read_string_u8(
        payload,
        offset
    )

    # Request.
    request, offset = read_string_u16(
        payload,
        offset
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
        "request": request
    }


# ============================================================
# PARSE NOTHREAT
# ============================================================

def parse_nothreat(payload):
    """
    NOTHREAT payload:

        [IP len u8]
        [IP]
        [REQ len u16]
        [REQ]
    """

    offset = 0

    ip, offset = read_string_u8(
        payload,
        offset
    )

    request, offset = read_string_u16(
        payload,
        offset
    )

    if offset != len(payload):

        raise ProtocolError(
            "Extra bytes in NOTHREAT message"
        )

    return {
        "type": "nothreat",
        "ip": ip,
        "request": request
    }


# ============================================================
# PARSE STATS
# ============================================================

def parse_stats(payload):
    """
    STATS payload:

        [Logs processed u64]
        [Threats detected u64]
        [Logs/sec u32]

    Total:

        8 + 8 + 4 = 20 bytes.
    """

    EXPECTED_SIZE = 20

    if len(payload) != EXPECTED_SIZE:

        raise ProtocolError(
            f"Invalid STATS size. "
            f"Expected {EXPECTED_SIZE}, "
            f"got {len(payload)}"
        )

    offset = 0

    logs_processed, offset = read_u64(
        payload,
        offset
    )

    threats_detected, offset = read_u64(
        payload,
        offset
    )

    logs_per_second, offset = read_u32(
        payload,
        offset
    )

    return {
        "type": "stats",
        "logs_processed": logs_processed,
        "threats_detected": threats_detected,
        "logs_per_second": logs_per_second
    }
    


# ============================================================
# PARSE COMPLETE RUST MESSAGE
# ============================================================

def parse_message(message):
    """
    Parse:

        [1-byte type][payload]

    The TCP layer has already consumed the 4-byte length.
    """

    if len(message) < 1:

        raise ProtocolError(
            "Message does not contain a type byte"
        )

    # First byte tells us the message type.
    message_type = message[0]

    # Everything after it is the payload.
    payload = message[1:]

    if message_type == TYPE_LOG:

        return parse_log(payload)

    elif message_type == TYPE_THREAT:

        return parse_threat(payload)

    elif message_type == TYPE_NOTHREAT:

        return parse_nothreat(payload)

    elif message_type == TYPE_STATS:

        return parse_stats(payload)
    
    else:

        raise ProtocolError(
            f"Unknown message type: {message_type}"
        )


# ============================================================
# RUST REQUEST CONNECTION :4000
# ============================================================

def connect_to_rust():
    """
    Connect Python to the Rust TCP server on port 4000.

    Direction:

        Python --TCP--> Rust :4000

    This socket is used ONLY for sending requests to Rust.
    """

    global rust_request_socket

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(5)

    print(
        f"[RUST:4000] Connecting to "
        f"{RUST_HOST}:{RUST_REQUEST_PORT}..."
    )

    sock.connect(
        (
            RUST_HOST,
            RUST_REQUEST_PORT
        )
    )

    # Persistent connection after the initial connect.
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

    print(
        f"[RUST:4000] Connected to Rust"
    )


def send_to_rust(data):
    """
    Send a complete protocol message to Rust over port 4000.
    """

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
            OSError
        ):

            rust_request_connected.clear()

            try:
                sock.close()
            except OSError:
                pass

            rust_request_socket = None

            raise ConnectionError(
                "Rust request connection was lost"
            )


# ============================================================
# RUST RESPONSE SERVER :4002
# ============================================================

def start_rust_response_server():
    """
    Python listens on port 4002.

    Rust connects to this port and sends responses/events.

    Direction:

        Rust --TCP--> Python :4002
    """

    global rust_response_socket

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (
            RUST_RESPONSE_HOST,
            RUST_RESPONSE_PORT
        )
    )

    server.listen(5)

    print(
        f"[RUST:4002] Listening for Rust "
        f"responses on "
        f"{RUST_RESPONSE_HOST}:{RUST_RESPONSE_PORT}"
    )

    while True:

        client_socket, client_address = (
            server.accept()
        )

        print(
            f"[RUST:4002] Rust connected from "
            f"{client_address}"
        )

        # If Rust reconnects, replace the previous connection.
        with rust_response_socket_lock:

            rust_response_socket.add(client_socket)


        thread = threading.Thread(
            target=handle_rust_response_connection,
            args=(
                client_socket,
                client_address
            ),
            daemon=True
        )

        thread.start()


def handle_rust_response_connection(
    client_socket,
    client_address
):
    """
    Read all Rust -> Python messages from the connection
    accepted on port 4002.

    Protocol:

        [4-byte length]
        [1-byte type]
        [payload]

    SEARCH responses are placed in the SEARCH queue.

    Other Rust messages are parsed and broadcast to all
    connected browsers.
    """

    global rust_response_socket

    try:

        while True:

            # ------------------------------------------------
            # Read message length
            # ------------------------------------------------

            length_bytes = recv_exact(
                client_socket,
                4
            )

            if length_bytes is None:

                raise ConnectionError(
                    "Rust closed the :4002 connection"
                )


            message_length = struct.unpack(
                ">I",
                length_bytes
            )[0]


            if message_length < 1:

                raise ProtocolError(
                    "Rust message length must be at least 1"
                )


            if message_length > MAX_MESSAGE_SIZE:

                raise ProtocolError(
                    f"Rust message too large: "
                    f"{message_length}"
                )


            # ------------------------------------------------
            # The length includes:
            #
            #     1-byte type + payload
            # ------------------------------------------------

            message = recv_exact(
                client_socket,
                message_length
            )

            if message is None:

                raise ConnectionError(
                    "Rust disconnected while "
                    "sending a message"
                )


            message_type = message[0]
            payload = message[1:]


            # =================================================
            # SEARCH RESPONSE
            # =================================================

            if message_type == TYPE_SEARCH:

                print(
                    "[RUST:4002] SEARCH response received"
                )

                search_response_queue.put(
                    payload
                )

                continue


            # =================================================
            # NORMAL RUST TELEMETRY
            # =================================================

            event = parse_rust_message(
                message
            )

            print(
                "[RUST:4002] Parsed:"
            )

            print(
                json.dumps(
                    event,
                    indent=4
                )
            )


            # Send live telemetry to all browser clients.
            broadcast_json(
                event
            )


    except (
        ConnectionError,
        ConnectionResetError,
        OSError,
        ProtocolError
    ) as error:

        print(
            f"[RUST:4002] Connection ended: "
            f"{error}"
        )


    finally:

        with rust_response_socket_lock:

            rust_response_socket.discard(client_socket)


        try:
            client_socket.close()
        except OSError:
            pass


# ============================================================
# SEARCH REQUEST BUILDER
# ============================================================

def build_search_message(request):
    """
    Build the SEARCH request sent to Rust:4000.

    Protocol:

        [4-byte length]
        [1-byte type = 5]
        [2-byte request length]
        [UTF-8 request]

    The 4-byte length counts everything AFTER itself.
    """

    request_bytes = request.encode(
        "utf-8"
    )

    request_length = len(
        request_bytes
    )

    if request_length > 65535:

        raise ProtocolError(
            "Search request is too long"
        )


    payload = struct.pack(
        ">H",
        request_length
    )

    payload += request_bytes


    message_length = (
        1 + len(payload)
    )


    return (
        struct.pack(
            ">I",
            message_length
        )
        + struct.pack(
            ">B",
            TYPE_SEARCH
        )
        + payload
    )


# ============================================================
# SEARCH RESPONSE PARSER
# ============================================================

def parse_search_response(payload):
    """
    Parse the SEARCH response payload.

    Expected Rust response:

        [TIMESTAMP][THREAT][IP][REQ]
        [TIMESTAMP][THREAT][IP][REQ]
        ...

    Each record is separated by '\\n'.
    """

    text = payload.decode(
        "utf-8",
        errors="replace"
    )

    results = []


    for line_number, line in enumerate(
        text.splitlines(),
        start=1
    ):

        line = line.strip()

        if not line:
            continue


        if not (
            line.startswith("[")
            and line.endswith("]")
        ):

            raise ProtocolError(
                f"Invalid SEARCH record at "
                f"line {line_number}: {line!r}"
            )


        content = line[1:-1]


        parts = content.split(
            "][",
            3
        )


        if len(parts) != 4:

            raise ProtocolError(
                f"Invalid SEARCH record at "
                f"line {line_number}: "
                f"expected "
                "[TIMESTAMP][THREAT][IP][REQ]"
            )


        timestamp = parts[0]
        threat = parts[1]
        ip = parts[2]
        request = parts[3]


        try:
            timestamp = int(timestamp)
        except ValueError:
            pass


        results.append({
            "timestamp": timestamp,
            "threat": threat,
            "ip": ip,
            "request": request
        })


    return results


# ============================================================
# RUST MESSAGE PARSER
# ============================================================

def parse_rust_message(message):
    """
    Parse a complete Rust message.

    message is:

        [1-byte type][payload]
    """

    if len(message) < 1:

        raise ProtocolError(
            "Rust message has no type byte"
        )


    message_type = message[0]
    payload = message[1:]


    if message_type == TYPE_LOG:

        return parse_log(
            payload
        )


    if message_type == TYPE_THREAT:

        return parse_threat(
            payload
        )


    if message_type == TYPE_NOTHREAT:

        return parse_nothreat(
            payload
        )


    if message_type == TYPE_STATS:

        return parse_stats(
            payload
        )


    if message_type == TYPE_SEARCH:

        results = parse_search_response(
            payload
        )

        return {
            "type": "search_response",
            "message_type": TYPE_SEARCH,
            "count": len(results),
            "results": results
        }


    raise ProtocolError(
        f"Unknown Rust message type: "
        f"{message_type}"
    )


# ============================================================
# SEARCH OPERATION
# ============================================================

def search_rust(request):
    """
    Execute one complete SEARCH transaction.

        Browser
           |
           | WebSocket
           v
        Python
           |
           | TCP :4000
           v
        Rust
           |
           | TCP :4002
           v
        Python
           |
           | WebSocket
           v
        Browser

    The protocol currently has no request-id, so SEARCH
    requests are serialized using search_lock.
    """

    with search_lock:

        # ----------------------------------------------------
        # Remove stale responses
        # ----------------------------------------------------

        while True:

            try:

                search_response_queue.get_nowait()

            except queue.Empty:

                break


        # ----------------------------------------------------
        # Build Rust SEARCH message
        # ----------------------------------------------------

        frame = build_search_message(
            request
        )


        # ----------------------------------------------------
        # Send through Python -> Rust :4000
        # ----------------------------------------------------

        send_to_rust(
            frame
        )


        print(
            f"[SEARCH] Sent to Rust: "
            f"{request!r}"
        )


        # ----------------------------------------------------
        # Wait for Rust -> Python :4002
        # ----------------------------------------------------

        try:

            payload = search_response_queue.get(
                timeout=30
            )

        except queue.Empty:

            raise TimeoutError(
                "Timed out waiting for Rust "
                "SEARCH response on port 4002"
            )


        # ----------------------------------------------------
        # Parse response
        # ----------------------------------------------------

        results = parse_search_response(
            payload
        )


        return {
            "type": "search_response",
            "message_type": TYPE_SEARCH,
            "query": request,
            "count": len(results),
            "results": results
        }


# ============================================================
# WEBSOCKET HANDSHAKE
# ============================================================

def perform_websocket_handshake(client_socket):
    """
    Perform the WebSocket HTTP Upgrade handshake.

    Browser initially sends something similar to:

        GET / HTTP/1.1
        Host: localhost:8000
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: <key>
        Sec-WebSocket-Version: 13

    We respond with:

        HTTP/1.1 101 Switching Protocols
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Accept: <accept-key>

    This upgrades the normal TCP connection into a
    WebSocket connection.
    """

    # --------------------------------------------------------
    # Receive HTTP handshake.
    # --------------------------------------------------------

    request = b""

    while b"\r\n\r\n" not in request:

        chunk = client_socket.recv(4096)

        if not chunk:

            raise ConnectionError(
                "Browser disconnected during "
                "WebSocket handshake"
            )

        request += chunk

        # Prevent an absurdly large handshake.
        if len(request) > 16384:

            raise ProtocolError(
                "WebSocket handshake too large"
            )

    # --------------------------------------------------------
    # Convert HTTP request bytes -> text.
    # --------------------------------------------------------

    try:

        request_text = request.decode(
            "utf-8"
        )

    except UnicodeDecodeError as error:

        raise ProtocolError(
            "Invalid UTF-8 WebSocket handshake"
        ) from error

    # --------------------------------------------------------
    # Parse HTTP headers.
    # --------------------------------------------------------

    headers = {}

    lines = request_text.split(
        "\r\n"
    )

    for line in lines[1:]:

        if ":" not in line:
            continue

        name, value = line.split(
            ":",
            1
        )

        headers[
            name.strip().lower()
        ] = value.strip()

    # --------------------------------------------------------
    # Verify Upgrade header.
    # --------------------------------------------------------

    if headers.get("upgrade", "").lower() != "websocket":

        raise ProtocolError(
            "Missing WebSocket Upgrade header"
        )

    # --------------------------------------------------------
    # Get client's WebSocket key.
    # --------------------------------------------------------

    websocket_key = headers.get(
        "sec-websocket-key"
    )

    if websocket_key is None:

        raise ProtocolError(
            "Missing Sec-WebSocket-Key"
        )

    # --------------------------------------------------------
    # WebSocket specification requires us to append this
    # fixed GUID to the client's key.
    # --------------------------------------------------------

    websocket_guid = (
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    )

    combined = (
        websocket_key +
        websocket_guid
    )

    # --------------------------------------------------------
    # SHA-1 hash.
    # --------------------------------------------------------

    sha1_result = hashlib.sha1(
        combined.encode("utf-8")
    ).digest()

    # --------------------------------------------------------
    # Base64 encode the SHA-1 result.
    # --------------------------------------------------------

    accept_key = base64.b64encode(
        sha1_result
    ).decode("utf-8")

    # --------------------------------------------------------
    # Build HTTP 101 response.
    # --------------------------------------------------------

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )

    # --------------------------------------------------------
    # Send handshake response.
    # --------------------------------------------------------

    client_socket.sendall(
        response.encode("utf-8")
    )


# ============================================================
# WEBSOCKET FRAME SENDING
# ============================================================

def send_websocket_frame(
    client_socket,
    payload,
    opcode=0x1
):
    """
    Send one WebSocket frame.

    opcode:

        0x1 = text
        0x2 = binary
        0x8 = close
        0x9 = ping
        0xA = pong

    For browser communication we mainly use:

        0x1 = text

    because our application data will be JSON.
    """

    # --------------------------------------------------------
    # Convert payload to bytes.
    # --------------------------------------------------------

    if isinstance(payload, str):

        payload = payload.encode(
            "utf-8"
        )

    # --------------------------------------------------------
    # FIN bit.
    #
    # 1 = this is the final frame.
    #
    # We currently send complete messages in one frame.
    # --------------------------------------------------------

    first_byte = 0x80 | opcode

    # --------------------------------------------------------
    # Determine payload length.
    # --------------------------------------------------------

    payload_length = len(payload)

    # --------------------------------------------------------
    # WebSocket payload length encoding.
    #
    # 0 - 125:
    #     length stored directly
    #
    # 126:
    #     next 2 bytes contain length
    #
    # 127:
    #     next 8 bytes contain length
    # --------------------------------------------------------

    if payload_length <= 125:

        header = struct.pack(
            "!BB",
            first_byte,
            payload_length
        )

    elif payload_length <= 65535:

        header = struct.pack(
            "!BBH",
            first_byte,
            126,
            payload_length
        )

    else:

        header = struct.pack(
            "!BBQ",
            first_byte,
            127,
            payload_length
        )

    # --------------------------------------------------------
    # Send header + payload.
    # --------------------------------------------------------

    client_socket.sendall(
        header + payload
    )


# ============================================================
# WEBSOCKET FRAME RECEIVING
# ============================================================

def receive_websocket_frame(client_socket):
    """
    Receive and decode one WebSocket frame from a browser.

    IMPORTANT:

    Browser -> server WebSocket frames are MASKED.

    Therefore we must:

        1. Read frame header
        2. Read masking key
        3. Read masked payload
        4. Unmask payload
    """

    # --------------------------------------------------------
    # Read first 2 bytes.
    # --------------------------------------------------------

    header = recv_exact(
        client_socket,
        2
    )

    if header is None:

        return None

    first_byte = header[0]
    second_byte = header[1]

    # --------------------------------------------------------
    # FIN bit.
    # --------------------------------------------------------

    fin = (
        first_byte & 0x80
    ) != 0

    # --------------------------------------------------------
    # Opcode.
    # --------------------------------------------------------

    opcode = (
        first_byte & 0x0F
    )

    # --------------------------------------------------------
    # MASK bit.
    # --------------------------------------------------------

    masked = (
        second_byte & 0x80
    ) != 0

    # --------------------------------------------------------
    # Initial payload length.
    # --------------------------------------------------------

    payload_length = (
        second_byte & 0x7F
    )

    # --------------------------------------------------------
    # Extended length.
    # --------------------------------------------------------

    if payload_length == 126:

        length_bytes = recv_exact(
            client_socket,
            2
        )

        payload_length = struct.unpack(
            "!H",
            length_bytes
        )[0]

    elif payload_length == 127:

        length_bytes = recv_exact(
            client_socket,
            8
        )

        payload_length = struct.unpack(
            "!Q",
            length_bytes
        )[0]

    # --------------------------------------------------------
    # Browser -> server frames MUST be masked.
    # --------------------------------------------------------

    if not masked:

        raise ProtocolError(
            "Client WebSocket frame is not masked"
        )

    # --------------------------------------------------------
    # Read masking key.
    # --------------------------------------------------------

    masking_key = recv_exact(
        client_socket,
        4
    )

    # --------------------------------------------------------
    # Read masked payload.
    # --------------------------------------------------------

    masked_payload = recv_exact(
        client_socket,
        payload_length
    )

    # --------------------------------------------------------
    # Unmask.
    #
    # WebSocket uses XOR.
    # --------------------------------------------------------

    payload = bytearray(
        payload_length
    )

    for i in range(payload_length):

        payload[i] = (
            masked_payload[i]
            ^ masking_key[i % 4]
        )

    payload = bytes(payload)

    # --------------------------------------------------------
    # Return decoded frame.
    # --------------------------------------------------------

    return {
        "fin": fin,
        "opcode": opcode,
        "payload": payload
    }


# ============================================================
# WEBSOCKET JSON MESSAGE
# ============================================================

def send_json_websocket(
    client_socket,
    data
):
    """
    Convert a Python object into JSON and send it as a
    WebSocket text frame.
    """

    message = json.dumps(
        data
    )

    send_websocket_frame(
        client_socket,
        message,
        opcode=0x1
    )


# ============================================================
# HANDLE ONE BROWSER
# ============================================================

def handle_websocket_client(
    client_socket,
    client_address
):
    """
    Handle one browser WebSocket connection.

    Steps:

        1. Perform HTTP Upgrade handshake
        2. Register browser
        3. Send connection message
        4. Read WebSocket frames
        5. Handle ping/close
        6. Remove browser when disconnected
    """

    print(
        f"[WS] Browser connecting: "
        f"{client_address}"
    )

    try:

        # ----------------------------------------------------
        # Step 1:
        # WebSocket handshake.
        # ----------------------------------------------------

        perform_websocket_handshake(
            client_socket
        )

        # ----------------------------------------------------
        # Step 2:
        # Register client.
        # ----------------------------------------------------

        with websocket_clients_lock:

            websocket_clients.add(
                client_socket
            )

            client_count = len(
                websocket_clients
            )

        print(
            f"[WS] Browser connected. "
            f"Clients: {client_count}"
        )

        # ----------------------------------------------------
        # Step 3:
        # Send confirmation message.
        # ----------------------------------------------------

        send_json_websocket(
            client_socket,
            {
                "type": "connection",
                "status": "connected",
                "message": (
                    "Connected to FlareWatch backend"
                )
            }
        )

        # ----------------------------------------------------
        # Step 4:
        # Continuously receive WebSocket frames.
        # ----------------------------------------------------

        while True:

            frame = receive_websocket_frame(
                client_socket
            )

            if frame is None:

                break

            opcode = frame["opcode"]

            # ------------------------------------------------
            # TEXT FRAME
            #
            # 0x1 = text
            # ------------------------------------------------

            if opcode == 0x1:

                try:

                    text = frame[
                        "payload"
                    ].decode("utf-8")

                    print(
                        f"[WS] Browser message: "
                        f"{text}"
                    )

                    data = json.loads(text)

                except UnicodeDecodeError:

                    send_json_websocket(
                        client_socket,
                        {
                            "type": "error",
                            "error": "Invalid UTF-8 WebSocket payload"
                        }
                    )

                    continue

                except json.JSONDecodeError as error:

                    send_json_websocket(
                        client_socket,
                        {
                            "type": "error",
                            "error": f"Invalid JSON: {error}"
                        }
                    )

                    continue

                # ------------------------------------------------
                # SEARCH
                #
                # Browser sends:
                #
                # {
                #     "totalFrameBytes": 12,
                #     "type": 5,
                #     "requestLength": 5,
                #     "request": "error"
                # }
                #
                # totalFrameBytes is a WebSocket/application
                # value supplied by the frontend. It is NOT used
                # to frame the TCP message to Rust.
                # ------------------------------------------------

                if data.get("type") == TYPE_SEARCH:

                    request = data.get("request")

                    if not isinstance(request, str):

                        send_json_websocket(
                            client_socket,
                            {
                                "type": "search_response",
                                "message_type": TYPE_SEARCH,
                                "query": "",
                                "count": 0,
                                "results": [],
                                "error": (
                                    "SEARCH request must "
                                    "contain a string 'request'"
                                )
                            }
                        )

                        continue

                    try:

                        result = search_rust(
                            request
                        )

                        # Send the structured Rust result
                        # back through THIS SAME WebSocket.
                        send_json_websocket(
                            client_socket,
                            result
                        )

                    except (
                        ConnectionError,
                        TimeoutError,
                        ProtocolError,
                        OSError
                    ) as error:

                        send_json_websocket(
                            client_socket,
                            {
                                "type": "search_response",
                                "message_type": TYPE_SEARCH,
                                "query": request,
                                "count": 0,
                                "results": [],
                                "error": str(error)
                            }
                        )

                else:

                    send_json_websocket(
                        client_socket,
                        {
                            "type": "error",
                            "error": (
                                f"Unsupported message type: "
                                f"{data.get('type')}"
                            )
                        }
                    )

            # ------------------------------------------------
            # CLOSE FRAME
            #
            # 0x8
            # ------------------------------------------------

            elif opcode == 0x8:

                # Reply with close frame.
                send_websocket_frame(
                    client_socket,
                    b"",
                    opcode=0x8
                )

                break

            # ------------------------------------------------
            # PING
            #
            # 0x9
            # ------------------------------------------------

            elif opcode == 0x9:

                send_websocket_frame(
                    client_socket,
                    frame["payload"],
                    opcode=0xA
                )

            # ------------------------------------------------
            # PONG
            #
            # 0xA
            # ------------------------------------------------

            elif opcode == 0xA:

                pass

            else:

                print(
                    f"[WS] Unsupported opcode: "
                    f"{opcode}"
                )

    except ProtocolError as error:

        print(
            f"[WS] Protocol error from "
            f"{client_address}: {error}"
        )

    except ConnectionError as error:

        print(
            f"[WS] Connection error from "
            f"{client_address}: {error}"
        )

    except OSError as error:

        print(
            f"[WS] Socket error from "
            f"{client_address}: {error}"
        )

    finally:

        # ----------------------------------------------------
        # Remove client from global set.
        # ----------------------------------------------------

        with websocket_clients_lock:

            websocket_clients.discard(
                client_socket
            )

            client_count = len(
                websocket_clients
            )

        # ----------------------------------------------------
        # Close socket.
        # ----------------------------------------------------

        try:

            client_socket.close()

        except OSError:

            pass

        print(
            f"[WS] Browser disconnected. "
            f"Clients: {client_count}"
        )


# ============================================================
# BROADCAST JSON TO ALL BROWSERS
# ============================================================

def broadcast_json(data):
    """
    Broadcast a JSON-compatible Python object to every
    currently connected browser.

    EVENT PROCESSING IS NOT USING THIS YET.

    It is implemented now so that the communication layer
    is ready for the next stage.
    """

    message = json.dumps(
        data
    )

    # --------------------------------------------------------
    # Make a snapshot of connected clients.
    # --------------------------------------------------------

    with websocket_clients_lock:

        clients = list(
            websocket_clients
        )

    # --------------------------------------------------------
    # Send to every browser.
    # --------------------------------------------------------

    disconnected_clients = []

    for client in clients:

        try:

            send_websocket_frame(
                client,
                message,
                opcode=0x1
            )

        except OSError:

            disconnected_clients.append(
                client
            )

    # --------------------------------------------------------
    # Remove clients that failed.
    # --------------------------------------------------------

    if disconnected_clients:

        with websocket_clients_lock:

            for client in disconnected_clients:

                websocket_clients.discard(
                    client
                )


# ============================================================
# WEBSOCKET SERVER
# ============================================================

def start_websocket_server():
    """
    Start the browser-facing WebSocket server.

    Port:

        4005
    """

    # --------------------------------------------------------
    # Create IPv4 TCP socket.
    #
    # WebSocket starts as a normal TCP connection.
    # --------------------------------------------------------

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # --------------------------------------------------------
    # Allow address reuse.
    # --------------------------------------------------------

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    # --------------------------------------------------------
    # Bind.
    # --------------------------------------------------------

    server.bind(
        (
            WS_HOST,
            WS_PORT
        )
    )

    # --------------------------------------------------------
    # Listen.
    # --------------------------------------------------------

    server.listen(5)

    print(
        f"[WS] WebSocket server listening on "
        f"ws://localhost:{WS_PORT}"
    )

    try:

        while True:

            # Wait for browser.
            client_socket, client_address = (
                server.accept()
            )

            # One thread per browser.
            thread = threading.Thread(
                target=handle_websocket_client,
                args=(
                    client_socket,
                    client_address
                ),
                daemon=True
            )

            thread.start()

    except OSError as error:

        print(
            f"[WS] Server error: {error}"
        )

    finally:

        server.close()

        print(
            "[WS] WebSocket server stopped"
        )


# ============================================================
# MAIN
# ============================================================

def main():
    """
    Start the complete backend.

    Ports:

        Rust :4000
            Rust listens.
            Python connects and sends requests.

        Python :4002
            Python listens.
            Rust connects and sends responses/events.

        Python WebSocket :4005
            Browser connects here.
    """

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Start :4002 BEFORE connecting to Rust.
    #
    # Rust needs Python's :4002 listener to be available
    # before Rust can establish its response connection.
    # --------------------------------------------------------

    rust_response_thread = threading.Thread(
        target=start_rust_response_server,
        daemon=True
    )

    rust_response_thread.start()


    # --------------------------------------------------------
    # Connect to Rust :4000
    # --------------------------------------------------------

    try:

        connect_to_rust()

    except OSError as error:

        print(
            f"[RUST:4000] Initial connection failed: "
            f"{error}"
        )

        print(
            "[RUST:4000] The WebSocket server will "
            "still start. Rust can be restarted and "
            "the request connection can be retried."
        )


    # --------------------------------------------------------
    # Start WebSocket server :4005
    # --------------------------------------------------------

    start_websocket_server()


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n[SERVER] Shutting down..."
        )