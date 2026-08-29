const net = require("net");

const client = net.createConnection({
    host: "127.0.0.1",
    port: 4003
}, () => {

    console.log("Connected to tcp_server.js");

    const event = {
        type: "threat",
        ip: "192.168.1.9",
        threat: "SQL_INJECTION",
        timestamp: Date.now()
    };

    client.write(JSON.stringify(event) + "\n");

    console.log("Sent:", event);
});