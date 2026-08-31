# FlareWatch — STDLIB.md

FlareWatch uses no third-party runtime dependencies. The following are the package-level replacements used in the project.

| Normally use | FlareWatch uses |
|---|---|
| `aho-corasick` | Hand-written Aho-Corasick implementation using Rust `Vec`, arrays, and `VecDeque` |
| `tokio` / `async-std` | Rust `std::thread` with `Arc` and `Mutex` |
| `serde` / `serde_json` | Purpose-built binary protocol with Rust standard-library byte/string operations |
| Higher-level Rust networking libraries | `std::net::TcpListener` and `TcpStream` |
| Search/indexing library | `HashMap<String, Vec<usize>>` inverted index |
| Collection/deduplication helper | Rust `HashSet` |
| Timing/benchmark helper | Rust `std::time::Instant` and `SystemTime` |
| `websockets` | Hand-written WebSocket server over Python `socket` |
| WebSocket handshake helper | Python `hashlib` + `base64` |
| Binary protocol/codec package | Python `struct` |
| `orjson` / `ujson` | Python `json` |
| Async/work-queue package | Python `threading` + `queue.Queue` |
| Regex helper package | Python `re` |
| Pydantic-style event models | Python `dataclasses` |
| Sliding-window collection helper | Python `collections.deque` |
| Per-key default-state helper | Python `collections.defaultdict` |
| Retry/backoff package | `time.sleep()` + explicit backoff logic |
| Chart.js / D3.js | Native Canvas API + `requestAnimationFrame` |
| React / Vue | Native browser DOM APIs |
| Browser WebSocket package | Native browser `WebSocket` API |
| Browser JSON helper | Native browser `JSON.parse()` / `JSON.stringify()` |

The two largest hand-written replacements are the Aho-Corasick matcher and the WebSocket server. Where the standard library does not provide the higher-level component directly, FlareWatch implements the required functionality itself rather than adding a dependency.
