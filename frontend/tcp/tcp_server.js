const net = require("net");
const http = require("http");


// =====================================================
// CONFIG
// =====================================================

const TCP_HOST = "0.0.0.0";
const TCP_PORT = 4003;

const HTTP_HOST = "0.0.0.0";
const HTTP_PORT = 4004;


// =====================================================
// CLIENT SETS
// =====================================================

// main.py TCP connections
const tcpClients = new Set();

// Browser SSE connections
const frontendClients = new Set();


// =====================================================
// PROCESS MESSAGE
// =====================================================

function processMessage(message) {

    console.log(`[TCP] Received: ${message}`);

    try {

        const event = JSON.parse(message);

        console.log("[TCP] Parsed event:");
        console.log(event);

        broadcastToFrontend(event);

    } catch (error) {

        console.error(
            "[TCP] Invalid JSON:",
            error.message
        );

    }
}


// =====================================================
// TCP SERVER
// main.py -> tcp_server.js :4003
// =====================================================

const tcpServer = net.createServer((socket) => {

    const clientAddress =
        `${socket.remoteAddress}:${socket.remotePort}`;

    console.log(
        `[TCP] Client connected: ${clientAddress}`
    );

    tcpClients.add(socket);

    socket.setEncoding("utf8");

    let buffer = "";


    socket.on("data", (data) => {

        console.log(
            `[TCP] Raw data received: ${JSON.stringify(data)}`
        );

        buffer += data;


        // -------------------------------------------------
        // Handle newline-delimited JSON
        // -------------------------------------------------

        while (buffer.includes("\n")) {

            const newlineIndex =
                buffer.indexOf("\n");

            const message =
                buffer
                    .slice(0, newlineIndex)
                    .trim();

            buffer =
                buffer.slice(newlineIndex + 1);

            if (!message) {
                continue;
            }

            processMessage(message);

        }


        // -------------------------------------------------
        // Handle JSON without newline
        // -------------------------------------------------

        const remaining = buffer.trim();

        if (remaining) {

            try {

                JSON.parse(remaining);

                buffer = "";

                processMessage(remaining);

            } catch (error) {

                // Probably an incomplete TCP packet.
                // Keep it in the buffer.

            }

        }

    });


    socket.on("close", () => {

        tcpClients.delete(socket);

        console.log(
            `[TCP] Client disconnected: ${clientAddress}`
        );

    });


    socket.on("error", (error) => {

        tcpClients.delete(socket);

        console.error(
            `[TCP] Socket error: ${error.message}`
        );

    });

});


// =====================================================
// TCP SERVER ERROR
// =====================================================

tcpServer.on("error", (error) => {

    console.error(
        `[TCP SERVER ERROR] ${error.message}`
    );

});


// =====================================================
// START TCP SERVER
// =====================================================

tcpServer.listen(
    TCP_PORT,
    TCP_HOST,
    () => {

        console.log("========================================");
        console.log("       FLAREWATCH TCP SERVER");
        console.log("========================================");

        console.log(
            `TCP listening on ${TCP_HOST}:${TCP_PORT}`
        );

    }
);


// =====================================================
// HTTP / SSE SERVER
// browser -> tcp_server.js :4004
// =====================================================

const httpServer = http.createServer((req, res) => {

    console.log(
        `[HTTP] ${req.method} ${req.url}`
    );


    // -------------------------------------------------
    // CORS
    // -------------------------------------------------

    res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
    );


    // =================================================
    // SSE ENDPOINT
    // =================================================

    if (req.url === "/events") {

        console.log(
            "[SSE] Frontend connected"
        );


        res.writeHead(200, {

            "Content-Type":
                "text/event-stream",

            "Cache-Control":
                "no-cache, no-transform",

            "Connection":
                "keep-alive",

            "Access-Control-Allow-Origin":
                "*"

        });


        // Send initial connection message

        const connectionMessage = {
            type: "connection",
            status: "connected",
            message: "Connected to FlareWatch SSE"
        };


        res.write(
            `data: ${JSON.stringify(connectionMessage)}\n\n`
        );


        frontendClients.add(res);


        console.log(
            `[SSE] Active frontend clients: ${frontendClients.size}`
        );


        // Keep connection alive
        const keepAlive = setInterval(() => {

            try {

                res.write(": keep-alive\n\n");

            } catch (error) {

                clearInterval(keepAlive);

                frontendClients.delete(res);

            }

        }, 15000);


        req.on("close", () => {

            clearInterval(keepAlive);

            frontendClients.delete(res);

            console.log(
                "[SSE] Frontend disconnected"
            );

            console.log(
                `[SSE] Active frontend clients: ${frontendClients.size}`
            );

        });


        return;
    }


    // =================================================
    // HEALTH CHECK
    // =================================================

    if (req.url === "/health") {

        const health = {

            status: "online",

            tcpPort: TCP_PORT,

            ssePort: HTTP_PORT,

            tcpClients: tcpClients.size,

            frontendClients: frontendClients.size

        };


        res.writeHead(200, {

            "Content-Type":
                "application/json",

            "Access-Control-Allow-Origin":
                "*"

        });


        res.end(
            JSON.stringify(
                health,
                null,
                2
            )
        );


        return;
    }


    // =================================================
    // SIMPLE TEST ENDPOINT
    // =================================================

    if (req.url === "/test") {

        const testEvent = {

            type: "threat",

            ip: "192.168.1.9",

            threat: "SQL_INJECTION",

            timestamp: Date.now()

        };


        console.log(
            "[TEST] Sending test event:"
        );

        console.log(testEvent);


        broadcastToFrontend(testEvent);


        res.writeHead(200, {

            "Content-Type":
                "application/json",

            "Access-Control-Allow-Origin":
                "*"

        });


        res.end(
            JSON.stringify({
                status: "sent",
                event: testEvent
            })
        );


        return;
    }


    // =================================================
    // ROOT
    // =================================================

    if (req.url === "/") {

        res.writeHead(200, {

            "Content-Type":
                "text/plain",

            "Access-Control-Allow-Origin":
                "*"

        });


        res.end(
            "FlareWatch TCP/SSE Server is running."
        );


        return;
    }


    // =================================================
    // NOT FOUND
    // =================================================

    res.writeHead(404, {

        "Content-Type":
            "text/plain",

        "Access-Control-Allow-Origin":
            "*"

    });


    res.end("Not Found");

});


// =====================================================
// HTTP SERVER ERROR
// =====================================================

httpServer.on("error", (error) => {

    console.error(
        `[HTTP SERVER ERROR] ${error.message}`
    );

});


// =====================================================
// START HTTP SERVER
// =====================================================

httpServer.listen(
    HTTP_PORT,
    HTTP_HOST,
    () => {

        console.log(
            `HTTP/SSE listening on ${HTTP_HOST}:${HTTP_PORT}`
        );

        console.log(
            `Frontend SSE: http://localhost:${HTTP_PORT}/events`
        );

        console.log(
            `Health check: http://localhost:${HTTP_PORT}/health`
        );

        console.log(
            `Test event:   http://localhost:${HTTP_PORT}/test`
        );

    }
);


// =====================================================
// BROADCAST TO FRONTEND
// =====================================================

function broadcastToFrontend(event) {

    const message =
        `data: ${JSON.stringify(event)}\n\n`;


    console.log(
        `[SSE] Broadcasting to ${frontendClients.size} frontend client(s)`
    );


    for (const client of frontendClients) {

        try {

            client.write(message);

        } catch (error) {

            frontendClients.delete(client);

            console.error(
                "[SSE] Failed to send event:",
                error.message
            );

        }

    }

}


// =====================================================
// GRACEFUL SHUTDOWN
// =====================================================

process.on("SIGINT", () => {

    console.log(
        "\nShutting down FlareWatch..."
    );


    for (const client of tcpClients) {

        client.destroy();

    }


    for (const client of frontendClients) {

        client.end();

    }


    tcpServer.close(() => {

        httpServer.close(() => {

            console.log(
                "FlareWatch stopped."
            );

            process.exit(0);

        });

    });

});