# FlareWatch

### Zero-Dependency High-Throughput SIEM & Threat Detection Engine

FlareWatch is a lightweight, real-time security monitoring system built around a simple idea: **ingest large volumes of network logs, detect suspicious activity quickly, understand how individual events relate to each other, and make the result visible in a live dashboard — without third-party runtime dependencies.**

The system combines a high-performance Rust detection engine with Python-based threat correlation and a vanilla HTML/CSS/JavaScript dashboard.

## What FlareWatch Does

FlareWatch processes network logs through several stages:

```text
Log Generator / Log Source
          │
          │ TCP
          ▼
   Rust Detection Engine
          │
          ├── Aho-Corasick threat detection
          ├── Log storage
          ├── Inverted-index search
          └── Security events
                    │
                    │ TCP
                    ▼
      Python Threat Engine
          │
          ├── Event correlation
          ├── Attack-chain detection
          ├── Anomaly detection
          ├── Threat scoring
          ├── Alert deduplication
          └── Incident generation
                    │
                    ▼
          Python Backend
          │
          ├── HTTP/API layer
          ├── Search bridge
          └── WebSocket server
                    │
                    │ WebSocket
                    ▼
             Web Dashboard
```

The project is designed for local systems, controlled log generation, authorized environments, and demonstrations. It is **not intended to replace an enterprise SIEM such as Splunk or ELK**.

---

## Key Features

### High-throughput TCP ingestion

The Rust engine listens for incoming log traffic over TCP and handles multiple connections concurrently.

Each incoming message is length-prefixed and decoded directly from the byte stream. The Rust server uses standard-library networking and threading primitives rather than a networking framework.

### Aho-Corasick threat detection

Instead of checking every security signature independently, FlareWatch uses a hand-written **Aho-Corasick multi-pattern matching engine**.

The engine builds:

```text
Patterns
   ↓
Trie
   ↓
Failure Links
   ↓
Output States
   ↓
State-machine traversal
```

This allows a log to be scanned against the complete signature set in a single pass.

The current threat signatures cover categories including:

- SQL injection
- Cross-site scripting (XSS)
- Path traversal
- Command injection
- Sensitive-access indicators
- SSRF
- LDAP injection
- XXE
- HTTP anomalies

### Security-event generation

When the Rust detector finds a matching signature, it classifies the event and forwards the security event to the Python analysis layer.

Normal logs and detected threats follow different message paths, allowing the analysis engine to concentrate on meaningful security activity while still retaining logs for search.

### Event correlation

The Python threat engine operates on events rather than isolated pattern matches.

It maintains per-IP state and looks for behavior such as:

- repeated failed logins
- successful login following brute-force activity
- administrative access after compromise
- suspicious endpoint reconnaissance
- rapid endpoint scanning
- request floods
- multi-stage attack sequences

For example:

```text
LOGIN_FAILED
LOGIN_FAILED
LOGIN_FAILED
LOGIN_FAILED
LOGIN_FAILED
        ↓
BRUTE_FORCE

LOGIN_SUCCESS
        ↓
COMPROMISED_ACCESS

ADMIN_ACCESS
        ↓
COMPROMISED_ADMIN

SQLI / SENSITIVE_ACCESS / PATH_TRAVERSAL
        ↓
MULTI_STAGE_ATTACK / ACCOUNT_COMPROMISE
```

The correlation layer also uses time windows, so events that are sufficiently far apart are not automatically treated as part of one attack.

### Threat scoring

Events contribute to an IP's threat score.

The engine maps scores into tiers:

```text
0–4    LOW
5–9    MEDIUM
10–14  HIGH
15+    CRITICAL
```

Scores also decay over time, preventing an old event from permanently keeping an IP at a high risk level.

### Anomaly and behavioral detection

Not every attack has to match a single signature.

The analysis engine also tracks behavioral patterns such as:

- request floods
- repeated access to sensitive endpoints
- endpoint scanning
- suspicious activity across short time windows

This lets FlareWatch detect activity that emerges from **behavior over time**, rather than only from one malicious request.

### Alert deduplication

Repeated attacks should not create an unreadable stream of identical alerts.

FlareWatch applies an alert cooldown per IP and incident type so repeated occurrences can be grouped instead of flooding the dashboard with duplicate incidents.

### In-memory inverted-index search

FlareWatch builds an inverted index in the Rust engine.

Conceptually:

```text
"error"  → [log IDs]
"login"  → [log IDs]
"sql"    → [log IDs]
```

A search therefore queries the index instead of scanning every stored log from scratch.

For example, searching for:

```text
error
```

can return all indexed logs containing the token.

### Live dashboard

The frontend is a single-page vanilla HTML/CSS/JavaScript dashboard.

It displays:

- current system status
- live log-rate information
- threat counts
- recent security events
- incident information
- attack visualization
- searchable log results
- configurable threat-rule information

The dashboard receives live telemetry through a native browser WebSocket connection.

The visual layer uses browser-native Canvas and DOM APIs rather than a frontend framework or charting package.

---

# Running FlareWatch

## Requirements

You need:

- Docker
- Docker Compose
- Python available on the host for running the log generator

The application itself is started through Docker Compose.

## 1. Start the system

From the project root:

```bash
docker-compose up --build -d
```

This builds the project images and starts the FlareWatch services in detached mode.

## 2. Open the dashboard

Once the containers are running, open:

**<http://localhost:5500/index.html>**

The dashboard connects to the backend's WebSocket service and begins displaying live system information as events arrive.

## 3. Generate traffic

From the **project root**, run:

```bash
python log_gen.py --rate 100
```

This starts the log generator at approximately 100 events per second.

You should then see the dashboard begin receiving traffic and updating its live metrics.

### Recommended demo rate

Start with:

```bash
python log_gen.py --rate 100
```

For a more aggressive load, increase the rate gradually.

**Important:** rates above roughly **1,000 logs/sec can cause the browser dashboard to lag**, even though the backend pipeline can continue processing traffic. The dashboard is a visualization layer, so its rendering workload is different from the raw ingestion workload.

For a smooth demonstration, `100` is a good starting point.

---

# Demo Walkthrough

A simple way to demonstrate FlareWatch is:

### 1. Start FlareWatch

```bash
docker-compose up --build -d
```

Then open:

```text
http://localhost:5500/index.html
```

### 2. Start normal traffic

```bash
python log_gen.py --rate 100
```

Watch the live metrics update.

### 3. Generate suspicious traffic

Use the log generator's supported attack/event traffic to introduce suspicious requests.

Examples represented by the detection system include:

```text
' OR 1=1; --
../../etc/passwd
<script>
```

These can be classified into threat categories such as:

```text
SQLI
XSS
PATH_TRAVERSAL
```

### 4. Demonstrate correlation

Feed a sequence of related events rather than a single malicious request.

For example:

```text
failed login ×5
        ↓
successful login
        ↓
admin access
        ↓
SQL injection / path traversal
```

The Python threat engine can turn these individual events into a higher-level incident rather than treating them as unrelated log entries.

### 5. Demonstrate search

Use the dashboard's log-search interface to search for a token such as:

```text
error
```

The request is bridged to the Rust engine, which queries the inverted index and returns the matching logs.

---

# Architecture

## Rust Detection Engine

Rust is responsible for the high-throughput, low-level processing path.

Its responsibilities include:

- TCP ingestion
- concurrent client handling
- length-prefixed protocol parsing
- Aho-Corasick pattern matching
- threat classification
- log storage
- inverted-index maintenance
- search
- sending security events to downstream services

The Rust engine listens for incoming traffic on TCP port `4000`.

It also maintains downstream TCP connections to the Python services for event and search communication.

## Python Threat Engine

The Python threat engine is the behavioral-analysis layer.

It receives events from Rust and maintains state such as:

- failed-login history
- reconnaissance history
- endpoint-scan history
- request-flood history
- attacker state
- per-IP threat scores
- recent alert timestamps

It uses these structures to detect higher-level incidents.

The engine communicates with the backend through TCP and can reconnect to the backend when a connection is lost.

## Python Backend

The Python backend is the browser-facing communication layer.

It handles:

- browser WebSocket connections
- Rust communication
- Rust response parsing
- search requests
- telemetry/event broadcasting

The backend implements the required WebSocket protocol directly over sockets.

The dashboard WebSocket is exposed on:

```text
localhost:4005
```

The exact internal service addresses are managed by the Docker environment.

## Frontend

The frontend is a single `index.html`.

It uses:

- HTML
- CSS
- vanilla JavaScript
- browser WebSocket APIs
- Canvas
- native DOM APIs
- browser storage where needed for UI state

No React, Vue, Chart.js, D3, or npm runtime is required.

---

# Protocol Design

FlareWatch uses small binary messages between the services rather than depending on a serialization framework.

Messages are length-prefixed and include a message-type byte.

The system uses message types for data such as:

```text
LOG
THREAT
NOTHREAT
STATS
EVENT
SEARCH
```

The Python side decodes the binary fields using standard-library operations such as `struct`, while Rust decodes the corresponding byte slices directly.

This keeps the Rust/Python boundary explicit and lightweight.

---

# Search Flow

A dashboard search follows this general path:

```text
Browser
   │
   │ search request
   ▼
Python Backend
   │
   ▼
Rust Engine
   │
   ▼
Inverted Index
   │
   ▼
Matching Logs
   │
   ▼
Python Backend
   │
   ▼
Browser
```

The Rust index maps normalized search tokens to the corresponding stored log positions.

The returned results are then parsed by Python and presented by the dashboard.

---

# Threat Detection vs. Threat Analysis

One of the central design choices in FlareWatch is separating **detection** from **analysis**.

### Rust answers

> "What suspicious thing is present in this individual log?"

Aho-Corasick matches the raw message against the threat signatures and classifies the resulting event.

### Python answers

> "What do these events mean together?"

The threat engine examines sequences, timing, repetition, and attacker state to produce higher-level incidents.

This separation keeps the performance-sensitive byte scanning path in Rust while leaving the more stateful correlation logic in Python.

---

# Zero-Dependency Design

FlareWatch is designed around the Zero Dependency Hackathon requirement.

The project deliberately avoids third-party runtime packages and instead uses standard-library/platform functionality plus implementations written specifically for FlareWatch.

Examples include:

```text
Aho-Corasick
    → hand-written Rust implementation

Concurrency
    → std::thread / synchronization primitives

TCP networking
    → std::net / Python socket

Binary protocol handling
    → direct byte operations / struct

WebSocket server
    → hand-written WebSocket implementation

Log search
    → in-memory HashMap-based inverted index

Frontend framework
    → native DOM APIs

Charting library
    → Canvas
```

See [`STDLIB.md`](STDLIB.md) for the complete package-replacement log.

---

# Project Structure

The exact repository layout may evolve, but the main components are:

```text
├── analysis
│   ├── Dockerfile
│   └── main.py
├── backend
│   ├── Dockerfile
│   └── main_server.py
├── deps-proof.txt
├── docker-compose.yml
├── engine
│   ├── aho_patterns.txt
│   ├── Cargo.lock
│   ├── Cargo.toml
│   ├── Dockerfile
│   ├── src
│   │   └── main.rs
│   └── target
│       ├── CACHEDIR.TAG
│       ├── debug
│       ├── flycheck0
│       ├── release
│       └── x86_64-pc-windows-gnu
├── frontend
│   ├── Dockerfile
│   ├── icon
│   │   └── icon.png
│   └── index.html
├── LICENSE
├── log_gen.py
├── README.md
└── STDLIB.md
└── ...
```

The repository also contains the project configuration, Docker configuration, threat-pattern data, and other supporting files required to run the complete system.

---

# Performance Notes

FlareWatch separates **ingestion performance** from **visualization performance**.

The Rust engine is designed to process incoming logs efficiently using direct TCP I/O and a multi-pattern Aho-Corasick state machine.

The browser dashboard, however, has to:

- receive events
- update the DOM
- update metrics
- animate Canvas elements
- render threat information

Because of that, extremely high generator rates can make the browser UI lag even when the underlying processing pipeline is still functioning.

For demonstration purposes:

```bash
python log_gen.py --rate 100
```

is recommended.

---

# Security Scope

FlareWatch is intended for:

- local security monitoring
- controlled testing
- authorized environments
- security demonstrations
- learning and experimentation

It is not positioned as a production replacement for a full enterprise SIEM.

Its detection model is signature- and behavior-based and therefore depends on the rules and correlation logic included in the project.

---

# Why FlareWatch?

Traditional security monitoring stacks often hide a large amount of functionality behind frameworks, packages, search engines, and external services.

FlareWatch takes the opposite approach.

It exposes the core engineering directly:

```text
Raw TCP
   ↓
Concurrent ingestion
   ↓
Aho-Corasick
   ↓
Threat detection
   ↓
Log indexing
   ↓
Event correlation
   ↓
Threat scoring
   ↓
Incident generation
   ↓
WebSocket telemetry
   ↓
Live dashboard
```

The project demonstrates how much of a real-time security monitoring pipeline can be built from standard-library primitives when the abstractions normally provided by third-party packages are implemented directly.

---

# Zero-Dependency Goal

FlareWatch is intended to demonstrate that a useful security-monitoring application does not need a large runtime dependency tree.

The project focuses on doing the underlying work directly:

- networking
- concurrent processing
- pattern matching
- indexing
- binary protocol handling
- event correlation
- visualization

The result is a self-contained system that can be built and started with:

```bash
docker-compose up --build -d
```

and exercised immediately with:

```bash
python log_gen.py --rate 100
```
