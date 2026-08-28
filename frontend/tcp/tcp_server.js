const net = require("net");
const http = require("http");
const fs = require("fs");
const path = require("path");


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

const tcpClients = new Set();
const frontendClients = new Set();


// =====================================================
// TCP SERVER
// main.py -> tcp_server.js
// =====================================================

const tcpServer = net.createServer((socket) => {

    const clientAddress =
        `${socket.remoteAddress}:${socket.remotePort}`;

    console.log(`[TCP] Client connected: ${clientAddress}`);

    tcpClients.add(socket);

    socket.setEncoding("utf8");

    let buffer = "";


    socket.on("data", (data) => {

        buffer += data;

        /*
         * TCP does not preserve message boundaries.
         * So we use newline-delimited JSON.
         */

        while (buffer.includes("\n")) {

            const newlineIndex = buffer.indexOf("\n");

            const message =
                buffer.slice(0, newlineIndex).trim();

            buffer = buffer.slice(newlineIndex + 1);

            if (!message) {
                continue;
            }

            console.log(`[TCP] Received: ${message}`);


            try {

                const event = JSON.parse(message);

                console.log("[TCP] Parsed event:");
                console.log(event);

                // Send event to all connected browsers
                broadcastToFrontend(event);

            } catch (error) {

                console.error(
                    "[TCP] Invalid JSON:",
                    error.message
                );

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
            `[TCP] Error: ${error.message}`
        );

    });

});


tcpServer.listen(TCP_PORT, TCP_HOST, () => {

    console.log("========================================");
    console.log("       FLAREWATCH TCP SERVER");
    console.log("========================================");
    console.log(`TCP listening on ${TCP_HOST}:${TCP_PORT}`);

});


// =====================================================
// HTTP SERVER
// Browser -> tcp_server.js
// =====================================================

const httpServer = http.createServer((req, res) => {

    /*
     * CORS
     */

    res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
    );


    // =================================================
    // SERVER-SENT EVENTS
    // =================================================

    if (req.url === "/events") {

        console.log("[SSE] Frontend connected");


        res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*"
        });


        /*
         * Tell browser connection is alive.
         */

        res.write(
            `data: ${JSON.stringify({
                type: "connection",
                status: "connected"
            })}\n\n`
        );


        frontendClients.add(res);


        req.on("close", () => {

            frontendClients.delete(res);

            console.log("[SSE] Frontend disconnected");

        });


        return;
    }


    // =================================================
    // HEALTH CHECK
    // =================================================

    if (req.url === "/health") {

        res.writeHead(200, {
            "Content-Type": "application/json"
        });

        res.end(
            JSON.stringify({
                status: "online"
            })
        );

        return;
    }


    // =================================================
    // SERVE FRONTEND HTML FILES
    // =================================================

    let requestedFile =
        req.url === "/" ? "/overview.html" : req.url;

    /*
     * Remove query string
     */

    requestedFile =
        requestedFile.split("?")[0];


    /*
     * Prevent path traversal
     */

    const fileName =
        path.basename(requestedFile);

    const filePath =
        path.join(__dirname, "..", fileName);


    fs.readFile(filePath, (error, data) => {

        if (error) {

            res.writeHead(404, {
                "Content-Type": "text/plain"
            });

            res.end("404 - File not found");

            return;
        }


        let contentType = "text/html";

        if (fileName.endsWith(".js")) {
            contentType = "application/javascript";
        }

        if (fileName.endsWith(".css")) {
            contentType = "text/css";
        }

        if (fileName.endsWith(".svg")) {
            contentType = "image/svg+xml";
        }


        res.writeHead(200, {
            "Content-Type": contentType
        });

        res.end(data);

    });

});


httpServer.listen(
    HTTP_PORT,
    HTTP_HOST,
    () => {

        console.log(
            `HTTP/SSE listening on ${HTTP_HOST}:${HTTP_PORT}`
        );

        console.log(
            `Frontend: http://localhost:${HTTP_PORT}`
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
        `[SSE] Broadcasting to ${frontendClients.size} client(s)`
    );


    for (const client of frontendClients) {

        try {

            client.write(message);

        } catch (error) {

            frontendClients.delete(client);

        }

    }

}


// =====================================================
// SHUTDOWN
// =====================================================

process.on("SIGINT", () => {

    console.log("\nShutting down FlareWatch...");


    for (const client of tcpClients) {
        client.destroy();
    }


    for (const client of frontendClients) {
        client.end();
    }


    tcpServer.close();
    httpServer.close();


    process.exit(0);

});