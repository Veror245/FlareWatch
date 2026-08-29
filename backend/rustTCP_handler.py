"""
FlareWatch Backend
==================

STANDARD LIBRARY ONLY.

No external Python packages are used.

This file contains:

    1. Rust -> Python TCP IPC server
    2. FlareWatch binary protocol parser
    3. Python -> Browser WebSocket server

Ports:

    Rust -> Python TCP IPC:
        4001

    Python -> Browser WebSocket:
        8000


Architecture:

                    RUST
                      |
                      | TCP :4001
                      | Binary protocol
                      v
             +--------------------+
             |   TCP IPC SERVER   |
             +---------+----------+
                       |
                       v
                PROTOCOL PARSER
                       |
                       v
                 Python dict
                       |
                       X
                EVENT HANDLING
                NOT IMPLEMENTED


                    BROWSER
                       |
                       | WebSocket
                       | TCP :8000
                       v
             +--------------------+
             | WEBSOCKET SERVER   |
             |                    |
             | HTTP Upgrade       |
             | Frame handling     |
             | JSON messages      |
             +--------------------+


Only Python standard-library modules are used:

    socket
    struct
    threading
    json
    hashlib
    base64
    time
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


# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# Rust -> Python TCP IPC
# ------------------------------------------------------------

TCP_HOST = "0.0.0.0"
TCP_PORT = 4002


# ------------------------------------------------------------
# Browser WebSocket server
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

        p= parse_stats(payload)
        print(p)
        return p
    
    else:

        raise ProtocolError(
            f"Unknown message type: {message_type}"
        )


# ============================================================
# TCP CLIENT HANDLER
# ============================================================

def handle_tcp_client(client_socket, client_address):
    """
    Handle one Rust TCP connection.

    Multiple protocol messages can travel over the same
    TCP connection.

    Event processing is intentionally NOT implemented yet.
    """

    print(
        f"[TCP] Rust connected: {client_address}"
    )

    try:

        while True:

            # ------------------------------------------------
            # Read 4-byte length.
            # ------------------------------------------------

            length_bytes = recv_exact(
                client_socket,
                4
            )

            if length_bytes is None:

                print(
                    f"[TCP] Rust disconnected: "
                    f"{client_address}"
                )

                break

            # ------------------------------------------------
            # Convert 4 bytes -> u32.
            #
            # >I:
            #
            # > = big-endian
            # I = unsigned 32-bit integer
            # ------------------------------------------------

            message_length = struct.unpack(
                ">I",
                length_bytes
            )[0]

            # print(
            #     f"[TCP] Message length: "
            #     f"{message_length}"
            # )

            # ------------------------------------------------
            # Validate length.
            # ------------------------------------------------

            if message_length < 1:

                raise ProtocolError(
                    "Message length must be at least 1"
                )

            if message_length > MAX_MESSAGE_SIZE:

                raise ProtocolError(
                    f"Message too large: "
                    f"{message_length}"
                )

            # ------------------------------------------------
            # Read complete message.
            # ------------------------------------------------

            message = recv_exact(
                client_socket,
                message_length
            )

            if message is None:

                raise ConnectionError(
                    "Rust disconnected while sending "
                    "a message"
                )

            # ------------------------------------------------
            # Decode protocol.
            # ------------------------------------------------

            event = parse_message(
                message
            )

            # ------------------------------------------------
            # EVENT PROCESSING IS NOT IMPLEMENTED YET.
            # ------------------------------------------------

            #print(f"[TCP] Parsed event: {event}")

    except ProtocolError as error:

        print(
            f"[TCP] Protocol error: {error}"
        )

    except ConnectionError as error:

        print(
            f"[TCP] Connection error: {error}"
        )

    except OSError as error:

        print(
            f"[TCP] Socket error: {error}"
        )

    finally:

        client_socket.close()

        print(
            f"[TCP] Connection closed: "
            f"{client_address}"
        )


# ============================================================
# TCP SERVER
# ============================================================

def start_tcp_server():
    """
    Start the Rust -> Python TCP server.
    """

    # --------------------------------------------------------
    # Create IPv4 TCP socket.
    # --------------------------------------------------------

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # --------------------------------------------------------
    # Allow address reuse when restarting server.
    # --------------------------------------------------------

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    # --------------------------------------------------------
    # Bind IP + port.
    # --------------------------------------------------------

    server.bind(
        (
            TCP_HOST,
            TCP_PORT
        )
    )

    # --------------------------------------------------------
    # Start listening.
    # --------------------------------------------------------

    server.listen(5)

    print(
        f"[TCP] IPC server listening on "
        f"{TCP_HOST}:{TCP_PORT}"
    )

    try:

        while True:

            # Wait for Rust.
            client_socket, client_address = server.accept()

            # One worker thread per TCP connection.
            thread = threading.Thread(
                target=handle_tcp_client,
                args=(
                    client_socket,
                    client_address,
                ),
                daemon=True
            )

            thread.start()

    except OSError as error:

        print(
            f"[TCP] Server error: {error}"
        )

    finally:

        server.close()

        print(
            "[TCP] Server stopped"
        )


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

                except UnicodeDecodeError:

                    print(
                        "[WS] Invalid UTF-8 text"
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

        8000
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
    Start both servers.

    TCP server:
        Rust -> Python
        port 4001

    WebSocket server:
        Browser -> Python
        port 8000
    """

    # --------------------------------------------------------
    # Start TCP server in its own thread.
    # --------------------------------------------------------

    tcp_thread = threading.Thread(
        target=start_tcp_server,
        daemon=True
    )

    tcp_thread.start()

    # --------------------------------------------------------
    # Start WebSocket server in the main thread.
    # --------------------------------------------------------

    start_websocket_server()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n[SERVER] Shutting down..."
        )