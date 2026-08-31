# FlareWatch — STDLIB.md

FlareWatch is a zero-dependency SIEM and threat-detection system built for the Zero Dependency Hackathon.

This document records the concrete third-party libraries or frameworks that would normally be used for the functionality implemented by FlareWatch, and the standard-library or native-platform mechanisms used instead.

The important distinction is that FlareWatch does **not** pretend the standard library provides every missing feature. Where the runtime has no built-in equivalent, the required application-specific layer is implemented directly.

---

## Dependency policy

### Rust

The Rust implementation uses only the Rust standard library. There are no third-party crates in the runtime.

### Python

The backend uses only Python standard-library modules. There is no third-party Python runtime package.

### Browser frontend

The dashboard is a self-contained HTML file using native browser APIs. There is no npm runtime dependency, frontend framework, charting library, or WebSocket client package.

This matches the hackathon's definition of zero dependency: the shipped artifact must have an empty runtime dependency manifest, and functionality normally supplied by packages should be documented here.  

---

# 1. Rust

The Rust engine is the high-throughput ingestion and detection layer. Its current implementation imports only standard-library functionality such as `VecDeque`, `HashMap`, `HashSet`, `TcpListener`, `TcpStream`, `Arc`, `Mutex`, `Read`, `Write`, and time APIs.

## 1.1 `aho-corasick` → hand-written Aho-Corasick

**Normally:** `aho-corasick`

**FlareWatch:** a custom Aho-Corasick implementation built from Rust standard-library primitives.

The implementation explicitly builds:

- trie nodes
- transition tables
- failure links
- output lists
- state-machine traversal

The trie node is represented with a fixed `[i32; 256]` transition table, a failure state, and a `Vec<usize>` of matching pattern IDs.

Failure links are constructed with a breadth-first traversal using `std::collections::VecDeque`.

No pattern-matching crate is involved.

This is the clearest Package Killer component in FlareWatch: the algorithm itself is implemented in the project rather than delegated to a crate.

## 1.2 `tokio` / `async-std` → `std::thread` + `std::sync`

**Normally:** `tokio` or `async-std` for concurrent network handling.

**FlareWatch:** OS threads plus standard synchronization primitives.

The TCP server accepts connections with `TcpListener` and creates a worker using `std::thread::spawn`. Shared state is protected with `Arc<Mutex<...>>`.

This is an intentional synchronous/threaded design rather than an external async runtime.

The hackathon specifically identifies `std::thread` and standard synchronization as the Rust zero-dependency concurrency approach because Rust's standard library does not provide an async executor.

## 1.3 `serde_json` → application-specific manual wire serialization

**Normally:** `serde` / `serde_json` for structured serialization.

**FlareWatch:** the Rust side constructs its wire messages directly using byte buffers and standard integer/string conversion APIs.

The engine uses an explicit binary message format with:

- a four-byte big-endian message length
- a message-type byte
- length-prefixed fields
- raw byte payloads

Examples include `u32::to_be_bytes()`, `u16::to_be_bytes()`, `Vec<u8>`, and `String::from_utf8_lossy()`.

For search results, Rust returns newline-separated records rather than requiring a general-purpose serialization framework.

This is not intended to be a general replacement for `serde_json`; it is a deliberately small protocol for FlareWatch's fixed message types.

## 1.4 Higher-level Rust networking → `std::net`

**Normally:** a higher-level networking stack such as `tokio`, `hyper`, or another TCP/HTTP abstraction.

**FlareWatch:**

```rust
std::net::{TcpListener, TcpStream}
```

The engine performs TCP ingestion and process-to-process communication directly with sockets.

The current server listens on TCP port `4000`, then opens downstream TCP connections to the analysis and backend services.

No Rust networking framework is required.

## 1.5 Search/indexing package → `HashMap` inverted index

**Normally:** a search/indexing library or external search engine.

**FlareWatch:** an in-memory inverted index implemented directly with standard collections.

The search structure is:

```text
HashMap<String, Vec<usize>>
```

and maps normalized tokens to the IDs/positions of matching stored logs.

The log store itself is a standard-library `Vec<String>`.

The result is a purpose-built keyword search layer without an indexing dependency.

## 1.6 Set/collection utility → `HashSet`

**Normally:** an external collection/helper package when deduplicating matches or maintaining a unique set.

**FlareWatch:** `std::collections::HashSet`.

The detection engine uses `HashSet<ThreatType>` to collapse duplicate threat classifications produced by multiple matching signatures.

No collection dependency is needed.

## 1.7 Shared-memory/concurrency helper → `Arc<Mutex<T>>`

**Normally:** external synchronization abstractions around shared engine state.

**FlareWatch:** `std::sync::Arc` and `std::sync::Mutex`.

The Aho-Corasick engine and inverted index are shared safely between worker threads through the standard library.

## 1.8 Benchmark/timing library → `std::time`

**Normally:** a timing/benchmark helper package.

**FlareWatch:** `std::time::Instant` and `std::time::SystemTime`.

`Instant` is used to measure processing intervals and calculate throughput. `SystemTime` is used for event timestamps.

No timing crate is required for the runtime measurements the application exposes.

---

# 2. Python backend

The current backend imports only:

```python
import socket
import struct
import json
import threading
import hashlib
import base64
import queue
import re
```

There is **no** `hmac` import, no TOTP implementation, no `pyotp`, no `PyJWT`, no Flask/FastAPI import, and no `http.server` import in the current backend.

That distinction matters: older project planning documents described an optional authentication layer, but it is not part of this current implementation and is therefore not claimed here.

## 2.1 `websockets` → hand-written WebSocket server

**Normally:** the Python `websockets` package or another WebSocket server framework.

**FlareWatch:** raw TCP sockets plus a custom RFC 6455 implementation.

The server implements the pieces needed by the dashboard itself:

- HTTP Upgrade handshake
- `Sec-WebSocket-Key` handling
- `Sec-WebSocket-Accept` calculation
- text frames
- variable payload lengths
- client masking/unmasking
- close frames
- ping/pong
- broadcasting
- multiple connected clients

The server is built directly on `socket.socket`, `recv`, and `sendall`.

This is one of FlareWatch's strongest zero-dependency implementations because the WebSocket protocol layer itself is written in the project.

## 2.2 WebSocket handshake dependency → `hashlib` + `base64`

The WebSocket handshake normally disappears behind the WebSocket package.

FlareWatch exposes the underlying primitives directly:

```python
hashlib.sha1(...)
base64.b64encode(...)
```

The server computes the RFC 6455 accept key itself rather than relying on a WebSocket framework to do it.

## 2.3 Binary protocol package → `struct`

**Normally:** a binary protocol/codec package.

**FlareWatch:** Python's standard-library `struct` module.

`struct.pack`, `struct.unpack`, and `struct.unpack_from` are used for the fixed-width fields in the Rust/Python wire protocol and WebSocket extended payload lengths.

The project therefore has an explicit, inspectable binary protocol instead of depending on a codec library.

## 2.4 JSON package → `json`

**Normally:** `orjson`, `ujson`, or another JSON package.

**FlareWatch:** Python's built-in `json` module.

The backend uses `json.loads()` for browser messages and `json.dumps()` for messages sent to the dashboard and diagnostic output.

This is a direct standard-library replacement and does not require a third-party JSON runtime.

## 2.5 Async framework / WebSocket worker runtime → `threading`

**Normally:** an async networking framework or external worker/runtime layer.

**FlareWatch:** `threading.Thread`.

Separate threads handle Rust connections, Dev2 connections, and browser WebSocket clients. Browser client send operations are additionally protected with standard `threading.Lock` instances.

## 2.6 External work queue → `queue.Queue`

**Normally:** an external queue/task coordination package.

**FlareWatch:** `queue.Queue`.

Search responses from the Rust process are coordinated through Python's standard thread-safe queue rather than an external message-queue dependency.

## 2.7 Regex package → `re`

**Normally:** a third-party regular-expression helper where application-specific parsing is required.

**FlareWatch:** Python's standard-library `re` module.

The backend uses a compiled regular expression to parse the newline-delimited search response records returned by Rust.

This is deliberately limited to the application's record format rather than introducing a parsing dependency.

## 2.8 HTTP/WebSocket framework routing → direct protocol handling

**Normally:** Flask/FastAPI/Socket.IO would hide much of the request and connection lifecycle.

**FlareWatch:** the backend directly handles the WebSocket Upgrade request, frame lifecycle, connection state, and browser message dispatch over sockets.

The current backend should therefore **not** be documented as a Flask/FastAPI or `http.server` replacement: it does not import or use either of those servers.

---

## 2.9 `pydantic`-style event models → `dataclasses.dataclass`

**Normally:** a validation/model package such as `pydantic` for lightweight structured event objects.

**FlareWatch:** Python's standard-library `dataclasses`.

The threat-analysis engine represents incoming events with a small `Event` dataclass containing fields such as IP address, event type, severity, endpoint, timestamp, and metadata. The source uses `@dataclass` and `field(default_factory=...)` directly from the standard library.

This is intentionally a simple in-process model; FlareWatch does not claim Pydantic-level schema validation.

## 2.10 Sliding-window / ordered collection helper → `collections.deque`

**Normally:** a helper library for efficient bounded queues or time-windowed collections.

**FlareWatch:** `collections.deque`.

The threat engine keeps recent events for failed-login, reconnaissance, endpoint-scan, and request-flood detection in deques. Old timestamps are removed from the left as their windows expire. This gives the correlation engine an efficient FIFO structure without a third-party dependency.

## 2.11 Grouping/default-map helper → `collections.defaultdict`

**Normally:** external convenience structures for automatically initialized per-key state.

**FlareWatch:** `collections.defaultdict`.

Per-IP trackers and threat-score state are keyed by IP address and initialized automatically using standard-library `defaultdict` instances. This keeps the correlation engine's state management small and dependency-free.

## 2.12 Retry/backoff package → `time.sleep` + explicit backoff loop

**Normally:** a retry/backoff package such as `tenacity`.

**FlareWatch:** a small explicit retry loop using `time.sleep()` and arithmetic backoff.

The threat engine reconnects to the backend by starting with a one-second delay and increasing the delay up to a configured maximum. No retry framework is needed for this focused connection task.

# 3. Browser frontend

The frontend is a self-contained HTML document with inline CSS and JavaScript.

It has no npm dependency tree and no third-party frontend runtime.

## 3.1 Chart.js / D3.js → Canvas API

**Normally:** Chart.js, D3.js, or another charting/visualization library.

**FlareWatch:** the browser's native Canvas APIs.

The dashboard draws its animated traffic visualization through:

```javascript
canvas.getContext('2d')
requestAnimationFrame(...)
```

The application therefore controls rendering directly instead of loading a charting library.

## 3.2 React / Vue → native DOM APIs

**Normally:** React, Vue, or another frontend framework.

**FlareWatch:** native browser DOM APIs.

The dashboard creates and updates interface elements through APIs such as `document`, element properties, event handlers, and ordinary JavaScript functions.

There is no component framework, virtual DOM runtime, or build-time frontend package required.

## 3.3 JavaScript WebSocket library → browser-native `WebSocket`

**Normally:** a client WebSocket package.

**FlareWatch:** the browser's built-in `WebSocket` API.

The dashboard opens a native connection to the Python server:

```javascript
new WebSocket('ws://localhost:4005')
```

No npm WebSocket client is necessary.

## 3.4 JSON package → browser-native `JSON`

**Normally:** a JavaScript JSON helper package.

**FlareWatch:** the browser's built-in `JSON.parse()` / `JSON.stringify()` APIs.

JSON support is already part of the browser platform, so the frontend does not need a serialization dependency.

## 3.5 Animation library → `requestAnimationFrame`

**Normally:** an animation helper/library.

**FlareWatch:** the native browser animation scheduling API `requestAnimationFrame`.

This is used for the live visualizations without a third-party animation runtime.

---

# 4. What is intentionally hand-written

Several important pieces are not "replaced by a standard-library package" because the relevant runtime simply does not ship those higher-level facilities.

### Aho-Corasick

Rust `std` does not provide a built-in Aho-Corasick matcher. FlareWatch therefore implements the trie, failure links, outputs, and traversal itself.

### WebSocket server

Python `std` does not provide the high-level WebSocket server used by FlareWatch. The project therefore implements the required protocol layer directly over TCP sockets.

### Rust application protocol

Rust `std` does not provide a JSON serializer. FlareWatch instead uses an explicit binary protocol tailored to its log, threat, stats, event, and search messages.

These are not hidden vendored dependencies. They are application code written for FlareWatch.

---

# 5. Dependency claims we deliberately do not make

FlareWatch does **not** claim to replace entire products such as Elasticsearch, Splunk, or a full SIEM platform.

Its search implementation is a focused in-memory inverted index.

It does **not** claim feature parity with `serde_json`.

Its Rust/Python protocol is purpose-built rather than a general serialization framework.

It does **not** claim to be a production replacement for a mature WebSocket server library.

The Python WebSocket implementation supports the functionality required by this dashboard and is intentionally smaller than a general-purpose WebSocket stack.

It does **not** claim to use Flask, FastAPI, `http.server`, HMAC authentication, or TOTP in the current submitted backend. Those features belong to earlier project designs and are not part of this source-controlled implementation.

---

# 6. Zero-dependency summary

| Would normally use | FlareWatch implementation |
|---|---|
| `aho-corasick` | Hand-written Aho-Corasick using Rust `Vec`, arrays, and standard collections |
| `tokio` / `async-std` | `std::thread`, `Arc`, `Mutex` |
| `serde` / `serde_json` | Purpose-built binary protocol and manual byte serialization |
| Higher-level Rust networking | `std::net::TcpListener` / `TcpStream` |
| Search/indexing library | `HashMap<String, Vec<usize>>` inverted index |
| Collection/dedup helper | `HashSet` |
| Timing/benchmark helper | `std::time::Instant` / `SystemTime` |
| Python `websockets` | Raw `socket` + hand-written RFC 6455 server |
| WebSocket handshake helper | `hashlib` + `base64` |
| Binary protocol/codec package | `struct` |
| `orjson` / `ujson` | Python `json` |
| Async/work queue package | `threading` + `queue.Queue` |
| Regex helper package | Python `re` |
| Chart.js / D3.js | HTML5 Canvas + `requestAnimationFrame` |
| React / Vue | Native DOM APIs |
| Browser WebSocket package | Native browser `WebSocket` |
| Browser JSON helper | Native `JSON` API |

---

## Final note

The strongest part of FlareWatch's zero-dependency approach is not merely avoiding imports. It is replacing the underlying layers where dependencies would normally hide the engineering:

```text
Aho-Corasick crate
        ↓
hand-written trie + failure links

WebSocket package
        ↓
raw TCP + RFC 6455 implementation

Serialization framework
        ↓
explicit application protocol

Search engine
        ↓
in-memory inverted index

Charting framework
        ↓
Canvas

Frontend framework
        ↓
native DOM
```

That is the standard-library engineering this submission is intended to demonstrate.
