"""
FlareWatch - Rust -> Python TCP IPC Server
============================================

This file contains BOTH:

1. The TCP server
2. The FlareWatch binary IPC protocol parser

Protocol:

    [4-byte length][1-byte type][payload]

All multi-byte integers are BIG-ENDIAN.

Strings are UTF-8.

Message Types:

    0 = LOG
    1 = THREAT
    2 = NOTHREAT
    3 = STATS


LOG payload:

    [IP len u8][IP][REQ len u16][REQ]


THREAT payload:

    [Threat type u8][IP len u8][IP][REQ len u16][REQ]


NOTHREAT payload:

    [IP len u8][IP][REQ len u16][REQ]


STATS payload:

    [Logs processed u64]
    [Threats detected u64]
    [Logs/sec u32]
"""

# ============================================================
# IMPORTS
# ============================================================

import socket
import struct
import threading


# ============================================================
# SERVER CONFIGURATION
# ============================================================

HOST = "0.0.0.0"

# FlareWatch specification:
# Rust -> Python IPC uses TCP port 4001.
PORT = 4001

# Maximum complete message that we will accept.
#
# This protects the server from a corrupted/malicious length
# field telling Python to allocate a huge amount of memory.
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB


# ============================================================
# MESSAGE TYPES
# ============================================================

TYPE_LOG = 0
TYPE_THREAT = 1
TYPE_NOTHREAT = 2
TYPE_STATS = 3


# ============================================================
# THREAT TYPES
# ============================================================

# The protocol image shows:
#
# 0 = SQL
# 1 = XSS
# 2 = BRUTE_FORCE
# 3 = PATH_TRAVERSAL
# ...
#
# Add more threat IDs here as your Rust implementation defines
# them.

THREAT_TYPES = {
    0: "SQL_INJECTION",
    1: "XSS",
    2: "BRUTE_FORCE",
    3: "PATH_TRAVERSAL",
}


# ============================================================
# CUSTOM PROTOCOL EXCEPTION
# ============================================================

class ProtocolError(Exception):
    """
    Raised when Rust sends data that does not follow
    the FlareWatch IPC protocol.
    """

    pass


# ============================================================
# RECEIVE EXACTLY N BYTES
# ============================================================

def recv_exact(sock, size):
    """
    Receive exactly `size` bytes from a TCP socket.

    IMPORTANT:
    TCP is a BYTE STREAM.

    If Rust sends:

        100 bytes

    Python is NOT guaranteed to receive:

        recv(100) -> 100 bytes

    It could receive:

        recv() -> 30 bytes
        recv() -> 40 bytes
        recv() -> 30 bytes

    Therefore this function keeps calling recv() until
    exactly `size` bytes have been received.

    Returns:
        bytes
        None if the client closes the connection before
        sending anything.
    """

    data = bytearray()

    while len(data) < size:

        chunk = sock.recv(size - len(data))

        # Empty bytes means the other side closed
        # the TCP connection.
        if not chunk:

            # If we haven't received anything yet,
            # this is a normal client disconnect.
            if len(data) == 0:
                return None

            # Otherwise the client disconnected
            # in the middle of a message.
            raise ConnectionError(
                "Connection closed before receiving "
                "the complete message"
            )

        data.extend(chunk)

    return bytes(data)


# ============================================================
# READ u8
# ============================================================

def read_u8(data, offset):
    """
    Read an unsigned 8-bit integer.

    u8 = 1 byte

    Example:

        03

    becomes:

        3
    """

    if offset + 1 > len(data):
        raise ProtocolError(
            "Not enough data to read u8"
        )

    value = data[offset]

    return value, offset + 1


# ============================================================
# READ u16
# ============================================================

def read_u16(data, offset):
    """
    Read an unsigned 16-bit integer.

    u16 = 2 bytes

    BIG-ENDIAN.

    Example:

        00 05

    becomes:

        5
    """

    if offset + 2 > len(data):
        raise ProtocolError(
            "Not enough data to read u16"
        )

    # > means BIG-ENDIAN
    # H means unsigned short / u16
    value = struct.unpack_from(
        ">H",
        data,
        offset
    )[0]

    return value, offset + 2


# ============================================================
# READ u32
# ============================================================

def read_u32(data, offset):
    """
    Read an unsigned 32-bit integer.

    u32 = 4 bytes

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
# READ u64
# ============================================================

def read_u64(data, offset):
    """
    Read an unsigned 64-bit integer.

    u64 = 8 bytes

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
# READ u8-LENGTH UTF-8 STRING
# ============================================================

def read_string_u8(data, offset):
    """
    Read:

        [length u8][UTF-8 string]

    Example:

        0A 31 39 32 2E 31 36 38 2E 31 2E 31

    means:

        length = 10
        string = "192.168.1.1"
    """

    # First byte tells us string length.
    length, offset = read_u8(
        data,
        offset
    )

    end = offset + length

    if end > len(data):
        raise ProtocolError(
            "String extends beyond message boundary"
        )

    string_bytes = data[offset:end]

    try:

        value = string_bytes.decode("utf-8")

    except UnicodeDecodeError as exc:

        raise ProtocolError(
            "Invalid UTF-8 string"
        ) from exc

    return value, end


# ============================================================
# READ u16-LENGTH UTF-8 STRING
# ============================================================

def read_string_u16(data, offset):
    """
    Read:

        [length u16][UTF-8 string]

    BIG-ENDIAN length.

    Used for the request field.
    """

    length, offset = read_u16(
        data,
        offset
    )

    end = offset + length

    if end > len(data):
        raise ProtocolError(
            "String extends beyond message boundary"
        )

    string_bytes = data[offset:end]

    try:

        value = string_bytes.decode("utf-8")

    except UnicodeDecodeError as exc:

        raise ProtocolError(
            "Invalid UTF-8 string"
        ) from exc

    return value, end


# ============================================================
# PARSE LOG
# ============================================================

def parse_log(payload):
    """
    Parse a LOG message.

    Payload:

        [IP len u8]
        [IP]
        [REQ len u16]
        [REQ]
    """

    offset = 0

    # Read IP address.
    ip, offset = read_string_u8(
        payload,
        offset
    )

    # Read request.
    request, offset = read_string_u16(
        payload,
        offset
    )

    # Make sure there is no unexpected data.
    if offset != len(payload):

        raise ProtocolError(
            "Extra bytes found at the end of LOG message"
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
    Parse a THREAT message.

    Payload:

        [Threat type u8]
        [IP len u8]
        [IP]
        [REQ len u16]
        [REQ]
    """

    offset = 0

    # Read threat ID.
    threat_type, offset = read_u8(
        payload,
        offset
    )

    # Convert threat ID into human-readable name.
    threat_name = THREAT_TYPES.get(
        threat_type,
        f"UNKNOWN_{threat_type}"
    )

    # Read IP.
    ip, offset = read_string_u8(
        payload,
        offset
    )

    # Read request.
    request, offset = read_string_u16(
        payload,
        offset
    )

    # Make sure the entire payload was consumed.
    if offset != len(payload):

        raise ProtocolError(
            "Extra bytes found at the end of THREAT message"
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
    Parse a NOTHREAT message.

    Payload:

        [IP len u8]
        [IP]
        [REQ len u16]
        [REQ]
    """

    offset = 0

    # Read IP.
    ip, offset = read_string_u8(
        payload,
        offset
    )

    # Read request.
    request, offset = read_string_u16(
        payload,
        offset
    )

    # Check for unexpected bytes.
    if offset != len(payload):

        raise ProtocolError(
            "Extra bytes found at the end of NOTHREAT message"
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
    Parse a STATS message.

    Payload:

        [Logs processed u64]
        [Threats detected u64]
        [Logs/sec u32]

    Total:

        8 + 8 + 4 = 20 bytes
    """

    EXPECTED_SIZE = 20

    if len(payload) != EXPECTED_SIZE:

        raise ProtocolError(
            f"Invalid STATS payload size. "
            f"Expected {EXPECTED_SIZE}, "
            f"received {len(payload)}"
        )

    offset = 0

    # Number of logs processed.
    logs_processed, offset = read_u64(
        payload,
        offset
    )

    # Number of threats detected.
    threats_detected, offset = read_u64(
        payload,
        offset
    )

    # Current logs/sec.
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
# PARSE COMPLETE MESSAGE
# ============================================================

def parse_message(message):
    """
    Parse one complete FlareWatch message.

    IMPORTANT:

    The TCP layer has already read the 4-byte length.

    Therefore `message` contains:

        [1-byte type][payload]

    The first byte tells us which parser to use.
    """

    if len(message) < 1:

        raise ProtocolError(
            "Message does not contain a type byte"
        )

    # First byte = message type.
    message_type = message[0]

    # Everything after type = payload.
    payload = message[1:]

    # LOG
    if message_type == TYPE_LOG:

        return parse_log(payload)

    # THREAT
    elif message_type == TYPE_THREAT:

        return parse_threat(payload)

    # NOTHREAT
    elif message_type == TYPE_NOTHREAT:

        return parse_nothreat(payload)

    # STATS
    elif message_type == TYPE_STATS:

        return parse_stats(payload)

    # Unknown message type
    else:

        raise ProtocolError(
            f"Unknown message type: {message_type}"
        )


# ============================================================
# HANDLE EVENTS
# ============================================================

def handle_event(event):
    """
    This function receives a fully decoded Python event.

    Currently we simply print the event.

    Later this is where we can connect the IPC layer to:

        - Threat Intelligence Engine
        - Metrics
        - HTTP API
        - WebSocket broadcasting
        - Log storage
    """

    event_type = event["type"]

    # --------------------------------------------------------
    # LOG
    # --------------------------------------------------------

    if event_type == "log":

        print(
            f"[LOG] "
            f"IP={event['ip']} "
            f"REQ={event['request']}"
        )

    # --------------------------------------------------------
    # THREAT
    # --------------------------------------------------------

    elif event_type == "threat":

        print(
            f"[THREAT] "
            f"TYPE={event['threat_name']} "
            f"IP={event['ip']} "
            f"REQ={event['request']}"
        )

    # --------------------------------------------------------
    # NOTHREAT
    # --------------------------------------------------------

    elif event_type == "nothreat":

        print(
            f"[NOTHREAT] "
            f"IP={event['ip']} "
            f"REQ={event['request']}"
        )

    # --------------------------------------------------------
    # STATS
    # --------------------------------------------------------

    elif event_type == "stats":

        print(
            f"[STATS] "
            f"LOGS={event['logs_processed']} "
            f"THREATS={event['threats_detected']} "
            f"LOGS/SEC={event['logs_per_second']}"
        )


# ============================================================
# HANDLE ONE RUST CONNECTION
# ============================================================

def handle_client(client_socket, client_address):
    """
    Handle one TCP connection from Rust.

    A single connection can contain:

        message 1
        message 2
        message 3
        ...
        message 50
        ...
        message N

    We continuously read messages until Rust disconnects.
    """

    print(
        f"[IPC] Rust connected from "
        f"{client_address}"
    )

    try:

        while True:

            # ------------------------------------------------
            # STEP 1
            # Read 4-byte message length
            # ------------------------------------------------

            length_bytes = recv_exact(
                client_socket,
                4
            )

            # None means Rust closed the connection.
            if length_bytes is None:

                print(
                    f"[IPC] Rust disconnected: "
                    f"{client_address}"
                )

                break

            # Convert 4 bytes into u32.
            #
            # >I means:
            #
            # > = BIG-ENDIAN
            # I = unsigned 32-bit integer
            message_length = struct.unpack(
                ">I",
                length_bytes
            )[0]

            # ------------------------------------------------
            # STEP 2
            # Validate length
            # ------------------------------------------------

            # At minimum, the message must contain
            # the 1-byte message type.
            if message_length < 1:

                raise ProtocolError(
                    f"Invalid message length: "
                    f"{message_length}"
                )

            # Protect against unreasonable sizes.
            if message_length > MAX_MESSAGE_SIZE:

                raise ProtocolError(
                    f"Message too large: "
                    f"{message_length} bytes"
                )

            # ------------------------------------------------
            # STEP 3
            # Read complete message
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

            # ------------------------------------------------
            # STEP 4
            # Parse binary protocol
            # ------------------------------------------------

            event = parse_message(message)

            # ------------------------------------------------
            # STEP 5
            # Give event to application
            # ------------------------------------------------

            handle_event(event)

    except ProtocolError as error:

        print(
            f"[IPC] Protocol error from "
            f"{client_address}: {error}"
        )

    except ConnectionError as error:

        print(
            f"[IPC] Connection error from "
            f"{client_address}: {error}"
        )

    except OSError as error:

        print(
            f"[IPC] Socket error from "
            f"{client_address}: {error}"
        )

    finally:

        client_socket.close()

        print(
            f"[IPC] Connection closed: "
            f"{client_address}"
        )


# ============================================================
# START SERVER
# ============================================================

def start_server():
    """
    Create and start the FlareWatch TCP IPC server.
    """

    # --------------------------------------------------------
    # Create TCP socket
    # --------------------------------------------------------

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # --------------------------------------------------------
    # Allow the server to reuse the port after restart.
    # --------------------------------------------------------

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    # --------------------------------------------------------
    # Bind IP + port
    # --------------------------------------------------------

    server.bind(
        (HOST, PORT)
    )

    # --------------------------------------------------------
    # Start listening.
    #
    # 5 = backlog for pending connection requests.
    # --------------------------------------------------------

    server.listen(5)

    print(
        f"[IPC] FlareWatch Python server "
        f"listening on {HOST}:{PORT}"
    )

    try:

        while True:

            # ------------------------------------------------
            # Wait for a Rust connection.
            # ------------------------------------------------

            client_socket, client_address = server.accept()

            # ------------------------------------------------
            # Create a worker thread for this connection.
            # ------------------------------------------------

            client_thread = threading.Thread(
                target=handle_client,
                args=(
                    client_socket,
                    client_address
                ),
                daemon=True
            )

            # Start worker.
            client_thread.start()

    except KeyboardInterrupt:

        print(
            "\n[IPC] Server shutting down..."
        )

    finally:

        server.close()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    start_server()