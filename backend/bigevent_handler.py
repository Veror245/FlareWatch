import socket
import struct
import json
import threading
import hashlib
import base64


# ============================================================
# CONFIGURATION
# ============================================================

# Dev 2 -> Dev 1
DEV2_HOST = "127.0.0.1"
DEV2_PORT = 4004

# Dev 1 -> Browser
WEBSOCKET_HOST = "0.0.0.0"
WEBSOCKET_PORT = 4005


# ============================================================
# OUTBOUND THREAT MAPPING
# ============================================================

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


# ============================================================
# MESSAGE TYPES
# ============================================================

# Dev 2 currently sends:
#
#     msg_type = 1
#
# in send_incident().
#
# Therefore we expect 1 here.

MESSAGE_TYPE_THREAT = 1


# ============================================================
# CONNECTED BROWSERS
# ============================================================

websocket_clients = set()

websocket_clients_lock = threading.Lock()


# ============================================================
# TCP HELPER
# ============================================================

def recv_exact(sock, num_bytes):
    """
    Receive exactly num_bytes from a TCP socket.

    TCP is a byte stream, so one sendall() from Dev 2
    does NOT necessarily correspond to one recv() here.
    """

    data = bytearray()

    while len(data) < num_bytes:

        chunk = sock.recv(
            num_bytes - len(data)
        )

        if not chunk:
            return None

        data.extend(chunk)

    return bytes(data)


# ============================================================
# PARSE INCIDENT FROM DEV 2
# ============================================================

def parse_incident(payload):
    """
    Parse the payload sent by Dev 2.

    Dev 2 sends:

        [1 byte] threat_id
        [1 byte] IP length
        [N bytes] IP
        [2 bytes] details length
        [N bytes] details

    The 4-byte total message length and the
    1-byte message type are handled outside this function.
    """

    offset = 0

    # --------------------------------------------------------
    # THREAT ID
    # --------------------------------------------------------

    if len(payload) < 1:
        raise ValueError("Missing threat ID")

    threat_id = payload[offset]

    offset += 1

    # --------------------------------------------------------
    # THREAT NAME
    # --------------------------------------------------------

    threat_name = OUTBOUND_THREATS.get(
        threat_id,
        f"UNKNOWN_THREAT_{threat_id}"
    )

    # --------------------------------------------------------
    # IP LENGTH
    # --------------------------------------------------------

    if offset + 1 > len(payload):
        raise ValueError("Missing IP length")

    ip_length = payload[offset]

    offset += 1

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    if offset + ip_length > len(payload):
        raise ValueError("Incomplete IP address")

    ip_bytes = payload[
        offset:offset + ip_length
    ]

    offset += ip_length

    ip = ip_bytes.decode(
        "utf-8",
        errors="replace"
    )

    # --------------------------------------------------------
    # DETAILS LENGTH
    # --------------------------------------------------------

    if offset + 2 > len(payload):
        raise ValueError("Missing details length")

    details_length = struct.unpack(
        ">H",
        payload[offset:offset + 2]
    )[0]

    offset += 2

    # --------------------------------------------------------
    # DETAILS
    # --------------------------------------------------------

    if offset + details_length > len(payload):
        raise ValueError("Incomplete details")

    details_bytes = payload[
        offset:offset + details_length
    ]

    offset += details_length

    details = details_bytes.decode(
        "utf-8",
        errors="replace"
    )

    # --------------------------------------------------------
    # MAKE SURE NOTHING IS LEFT OVER
    # --------------------------------------------------------

    if offset != len(payload):

        raise ValueError(
            f"Unexpected {len(payload) - offset} "
            f"extra bytes in incident"
        )

    # --------------------------------------------------------
    # BROWSER-FACING EVENT
    # --------------------------------------------------------

    return {
        "type": "big_event",
        "message_type": MESSAGE_TYPE_THREAT,
        "threat_id": threat_id,
        "threat_name": threat_name,
        "ip": ip,
        "details": details,
    }


# ============================================================
# HANDLE DEV 2 TCP CONNECTION
# ============================================================

def handle_dev2_client(
    conn,
    addr
):
    """
    Handle the connection from Dev 2.

    Dev 2 can send multiple incidents over
    the same TCP connection.
    """

    print(
        f"[DEV2] Connected from {addr}"
    )

    try:

        while True:

            # ------------------------------------------------
            # 1. Read 4-byte message length
            # ------------------------------------------------

            length_bytes = recv_exact(
                conn,
                4
            )

            if length_bytes is None:
                break

            message_length = struct.unpack(
                ">I",
                length_bytes
            )[0]

            # ------------------------------------------------
            # Safety check
            # ------------------------------------------------

            if message_length > 1024 * 1024:

                raise ValueError(
                    "Message too large"
                )

            # ------------------------------------------------
            # 2. Read 1-byte message type
            # ------------------------------------------------

            type_bytes = recv_exact(
                conn,
                1
            )

            if type_bytes is None:
                break

            message_type = type_bytes[0]

            # ------------------------------------------------
            # 3. Read payload
            # ------------------------------------------------

            payload = recv_exact(
                conn,
                message_length
            )

            if payload is None:
                break

            # ------------------------------------------------
            # 4. Make sure this is a THREAT message
            # ------------------------------------------------

            if message_type != MESSAGE_TYPE_THREAT:

                print(
                    f"[DEV2] Ignoring unknown "
                    f"message type: {message_type}"
                )

                continue

            # ------------------------------------------------
            # 5. Parse incident
            # ------------------------------------------------

            event = parse_incident(
                payload
            )

            # ------------------------------------------------
            # 6. DEBUG OUTPUT
            # ------------------------------------------------

            print(
                "\n[DEV2 -> DEV1] Incident received:"
            )

            print(
                json.dumps(
                    event,
                    indent=4
                )
            )

            # ------------------------------------------------
            # 7. Send to browsers
            # ------------------------------------------------

            broadcast_json(
                event
            )

    except (
        ValueError,
        ConnectionError,
        OSError
    ) as error:

        print(
            f"[DEV2] Error: {error}"
        )

    finally:

        conn.close()

        print(
            f"[DEV2] Disconnected: {addr}"
        )


# ============================================================
# START DEV 2 TCP SERVER
# ============================================================

def start_dev2_server():

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
            DEV2_HOST,
            DEV2_PORT
        )
    )

    server.listen(5)

    print(
        f"[DEV1] Waiting for Dev 2 "
        f"on {DEV2_HOST}:{DEV2_PORT}"
    )

    while True:

        conn, addr = server.accept()

        thread = threading.Thread(
            target=handle_dev2_client,
            args=(conn, addr),
            daemon=True
        )

        thread.start()


# ============================================================
# WEBSOCKET HANDSHAKE
# ============================================================

def perform_websocket_handshake(
    client_socket
):
    """
    Convert the browser's HTTP connection
    into a WebSocket connection.
    """

    request = b""

    while b"\r\n\r\n" not in request:

        chunk = client_socket.recv(
            4096
        )

        if not chunk:

            raise ConnectionError(
                "Browser disconnected during handshake"
            )

        request += chunk

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
            1
        )

        headers[
            name.strip().lower()
        ] = value.strip()

    websocket_key = headers.get(
        "sec-websocket-key"
    )

    if websocket_key is None:

        raise ValueError(
            "Missing Sec-WebSocket-Key"
        )

    websocket_guid = (
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    )

    accept_hash = hashlib.sha1(
        (
            websocket_key +
            websocket_guid
        ).encode(
            "utf-8"
        )
    ).digest()

    accept_key = base64.b64encode(
        accept_hash
    ).decode(
        "utf-8"
    )

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )

    client_socket.sendall(
        response.encode(
            "utf-8"
        )
    )


# ============================================================
# SEND WEBSOCKET FRAME
# ============================================================

def send_websocket_frame(
    client_socket,
    payload,
    opcode=0x1
):
    """
    Send one WebSocket frame.

    opcode 0x1 = text.
    """

    if isinstance(
        payload,
        str
    ):

        payload = payload.encode(
            "utf-8"
        )

    first_byte = (
        0x80 | opcode
    )

    payload_length = len(
        payload
    )

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

    client_socket.sendall(
        header + payload
    )


# ============================================================
# SEND JSON
# ============================================================

def send_json_websocket(
    client_socket,
    data
):
    """
    Convert Python dictionary to JSON
    and send it as a WebSocket text frame.
    """

    message = json.dumps(
        data
    )

    send_websocket_frame(
        client_socket,
        message
    )


# ============================================================
# BROADCAST JSON
# ============================================================

def broadcast_json(data):
    """
    Send the event to every connected browser.
    """

    message = json.dumps(
        data
    )

    # Take a snapshot so the set can safely
    # change while we're sending.
    with websocket_clients_lock:

        clients = list(
            websocket_clients
        )

    dead_clients = []

    for client in clients:

        try:

            send_websocket_frame(
                client,
                message
            )

        except OSError:

            dead_clients.append(
                client
            )

    # Remove dead browsers.
    if dead_clients:

        with websocket_clients_lock:

            for client in dead_clients:

                websocket_clients.discard(
                    client
                )


# ============================================================
# RECEIVE WEBSOCKET FRAME
# ============================================================

def receive_websocket_frame(
    client_socket
):
    """
    Receive one WebSocket frame from the browser.

    We mainly need this so that the server can
    handle browser close/ping frames.
    """

    header = recv_exact(
        client_socket,
        2
    )

    if header is None:
        return None

    first_byte = header[0]
    second_byte = header[1]

    opcode = first_byte & 0x0F

    masked = (
        second_byte & 0x80
    ) != 0

    payload_length = (
        second_byte & 0x7F
    )

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

    if not masked:

        raise ValueError(
            "Browser frame was not masked"
        )

    masking_key = recv_exact(
        client_socket,
        4
    )

    masked_payload = recv_exact(
        client_socket,
        payload_length
    )

    payload = bytearray(
        payload_length
    )

    for i in range(
        payload_length
    ):

        payload[i] = (
            masked_payload[i]
            ^ masking_key[i % 4]
        )

    return {
        "opcode": opcode,
        "payload": bytes(payload)
    }


# ============================================================
# HANDLE BROWSER
# ============================================================

def handle_websocket_client(
    client_socket,
    client_address
):
    """
    Manage one browser WebSocket connection.
    """

    try:

        perform_websocket_handshake(
            client_socket
        )

        # Add browser.
        with websocket_clients_lock:

            websocket_clients.add(
                client_socket
            )

        print(
            f"[WS] Browser connected: "
            f"{client_address}"
        )

        # Send connection confirmation.
        send_json_websocket(
            client_socket,
            {
                "type": "connection",
                "status": "connected"
            }
        )

        # Wait for browser messages.
        while True:

            frame = receive_websocket_frame(
                client_socket
            )

            if frame is None:
                break

            opcode = frame[
                "opcode"
            ]

            # CLOSE
            if opcode == 0x8:

                send_websocket_frame(
                    client_socket,
                    b"",
                    opcode=0x8
                )

                break

            # PING
            elif opcode == 0x9:

                send_websocket_frame(
                    client_socket,
                    frame["payload"],
                    opcode=0xA
                )

    except (
        ValueError,
        ConnectionError,
        OSError
    ) as error:

        print(
            f"[WS] Error: {error}"
        )

    finally:

        with websocket_clients_lock:

            websocket_clients.discard(
                client_socket
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
# START WEBSOCKET SERVER
# ============================================================

def start_websocket_server():

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
            WEBSOCKET_HOST,
            WEBSOCKET_PORT
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
                client_address
            ),
            daemon=True
        )

        thread.start()


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Start Dev 2 receiver in background.
    # --------------------------------------------------------

    tcp_thread = threading.Thread(
        target=start_dev2_server,
        daemon=True
    )

    tcp_thread.start()

    # --------------------------------------------------------
    # Start WebSocket server.
    # --------------------------------------------------------

    start_websocket_server()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()