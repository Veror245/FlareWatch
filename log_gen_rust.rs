// log_gen.rs
use std::env;
use std::io::Write;
use std::net::TcpStream;
use std::time::{Duration, Instant};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 4000;
const DEFAULT_RATE: f64 = 100_000.0; // logs/sec; 0 = max speed
const BATCH_SIZE: usize = 50000;

fn encode_log(ip: &str, request: &str) -> Vec<u8> {
    let ip_bytes = ip.as_bytes();
    let req_bytes = request.as_bytes();
    let mut payload = Vec::with_capacity(1 + 1 + ip_bytes.len() + 2 + req_bytes.len());
    payload.push(ip_bytes.len() as u8);
    payload.extend_from_slice(ip_bytes);
    payload.extend_from_slice(&(req_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(req_bytes);

    let body_len = 1 + payload.len(); // type byte + payload
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_be_bytes());
    frame.push(0); // type LOG
    frame.extend_from_slice(&payload);
    frame
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut host = DEFAULT_HOST.to_string();
    let mut port = DEFAULT_PORT;
    let mut rate = DEFAULT_RATE;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                if i + 1 < args.len() {
                    host = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Missing value for --host");
                    return;
                }
            }
            "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(DEFAULT_PORT);
                    i += 2;
                } else {
                    eprintln!("Missing value for --port");
                    return;
                }
            }
            "--rate" => {
                if i + 1 < args.len() {
                    rate = args[i + 1].parse().unwrap_or(DEFAULT_RATE);
                    i += 2;
                } else {
                    eprintln!("Missing value for --rate");
                    return;
                }
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                return;
            }
        }
    }

    println!("FlareWatch Log Generator (Rust)");
    println!("================================");
    println!("Destination : {}:{}", host, port);
    if rate > 0.0 {
        println!("Target rate : {:.0} logs/sec", rate);
    } else {
        println!("Target rate : MAX");
    }
    println!("Batch size  : {}", BATCH_SIZE);
    println!();

    // Prepare frames
    let normal_ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
        "192.168.1.15",
    ];
    let normal_requests = [
        "GET / HTTP/1.1",
        "GET /home HTTP/1.1",
        "GET /login HTTP/1.1",
        "GET /logout HTTP/1.1",
        "GET /products HTTP/1.1",
        "GET /products/1 HTTP/1.1",
        "GET /products/2 HTTP/1.1",
        "GET /api HTTP/1.1",
        "GET /api/users HTTP/1.1",
        "GET /api/products HTTP/1.1",
        "GET /search?q=laptop HTTP/1.1",
        "GET /about HTTP/1.1",
        "GET /contact HTTP/1.1",
        "GET /dashboard HTTP/1.1",
        "GET /profile HTTP/1.1",
        "GET /settings HTTP/1.1",
    ];
    let attack_ips = [
        "10.0.0.5",
        "10.0.0.23",
        "10.0.0.42",
        "172.16.0.99",
        "192.168.1.200",
    ];

    let sqli = [
        "' OR 1=1",
        "' OR '1'='1",
        "\" OR 1=1",
        "\" OR \"1\"=\"1\"",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' AND 1=1",
        "' AND '1'='1",
        "' AND 1=2",
        "\" AND 1=1",
        "\" AND 1=2",
        "UNION SELECT",
        "UNION ALL SELECT",
        "UNION DISTINCT SELECT",
        "UNION SELECT NULL",
        "UNION ALL SELECT NULL",
        "SELECT * FROM",
        "SELECT username",
        "SELECT password",
        "FROM users",
        "FROM information_schema",
        "DROP TABLE",
        "DROP DATABASE",
        "INSERT INTO",
        "DELETE FROM",
        "UPDATE users",
        "ALTER TABLE",
        "OR 1=1",
        "AND 1=1",
        "OR TRUE",
        "AND TRUE",
        "OR 'x'='x",
    ];
    let xss = [
        "<script",
        "</script>",
        "<script>",
        "<script src=",
        "javascript:",
        "javascript://",
        "vbscript:",
        "data:text/html",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "onblur=",
        "onchange=",
        "onsubmit=",
        "onkeydown=",
        "onkeyup=",
        "<iframe",
        "<iframe src=",
        "<object",
        "<embed",
        "<svg",
        "<svg onload=",
        "<img src=",
        "<img onerror=",
        "<body onload=",
        "<input onfocus=",
        "<details open",
    ];
    let path_traversal = [
        "../",
        "../../",
        "../../../",
        "../../../../",
        "../etc/",
        "../../etc/",
        "../../etc/passwd",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/issue",
        "/proc/self/",
        "proc/self/environ",
        "..\\",
        "..\\..\\",
        "..\\..\\..\\",
        "..\\windows\\",
        "..\\windows\\system32",
        "windows/system32",
        "windows/win.ini",
        "win.ini",
        "boot.ini",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%2f",
        "%2e%2e%5c",
        "..%5c",
        "%252e%252e%252f",
    ];
    let command_injection = [
        "; whoami",
        "; id",
        "; ls",
        "; cat",
        "; pwd",
        "| whoami",
        "| id",
        "| ls",
        "&& whoami",
        "&& id",
        "&& ls",
        "|| whoami",
        "|| id",
        "$(whoami)",
        "$(id)",
        "$(cat /etc/passwd)",
        "`whoami`",
        "`id`",
        "`cat /etc/passwd`",
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/bin/dash",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "whoami",
        "/etc/passwd",
        "id",
        "uname -a",
        "ifconfig",
        "ipconfig",
        "netstat",
    ];
    let sensitive_access = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config",
        "/config.php",
        "/config.yml",
        "/config.yaml",
        "/config.json",
        "/.git/",
        "/.git/config",
        "/.git/HEAD",
        "/.git/index",
        "id_rsa",
        "id_ed25519",
        "authorized_keys",
        ".ssh/",
        "wp-config.php",
        "web.config",
        ".htaccess",
        ".htpasswd",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
    ];
    let ssrf = [
        "localhost",
        "127.0.0.1",
        "127.0.0.0",
        "0.0.0.0",
        "::1",
        "10.0.0.1",
        "10.10.10.10",
        "192.168.1.1",
        "192.168.0.1",
        "172.16.0.1",
        "172.20.0.1",
        "172.31.255.255",
        "169.254.169.254",
        "/latest/meta-data",
        "/latest/user-data",
        "metadata.google.internal",
    ];
    let ldap_injection = [
        "*)(uid=*",
        "*)(cn=*",
        "*)(objectClass=*",
        "(|(uid=",
        "(|(cn=",
        "(&(uid=",
        "(&(cn=",
        "*))",
        "*))(",
    ];
    let xxe = [
        "<!DOCTYPE",
        "<!ENTITY",
        "SYSTEM \"",
        "SYSTEM '",
        "PUBLIC \"",
        "PUBLIC '",
        "file://",
        "php://",
        "expect://",
    ];
    let http_anomalies = [
        "INVALID_METHOD /login",
        "GET /login",
        "GET / HTTP/9.9",
        "Content-Length: 100 Content-Length: 500",
        "Content-Length: -1",
        "OVERSIZED_REQUEST",
        "OVERSIZED_HEADER",
        "INVALID_HEADER",
        "Transfer-Encoding: invalid",
        "INVALID_CHUNKED_ENCODING",
    ];

    // Build pools
    let mut normal_pool = Vec::new();
    for ip in &normal_ips {
        for req in &normal_requests {
            normal_pool.push(encode_log(ip, req));
        }
    }

    let mut auth_pool = Vec::new();
    for ip in &normal_ips {
        auth_pool.push(encode_log(ip, "LOGIN_FAILED user=user"));
        auth_pool.push(encode_log(ip, "LOGIN_SUCCESS user=user"));
        auth_pool.push(encode_log(ip, "ADMIN_ACCESS /admin"));
    }

    let mut threat_pool = Vec::new();

    // SQLi
    for pattern in &sqli {
        for ip in &attack_ips {
            let req = format!("GET /login?user=admin{} HTTP/1.1", pattern);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // XSS
    for pattern in &xss {
        for ip in &attack_ips {
            let req = format!("GET /search?q={} HTTP/1.1", pattern);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // Path traversal
    for pattern in &path_traversal {
        for ip in &attack_ips {
            let req = format!("GET /download?file={} HTTP/1.1", pattern);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // Command injection
    for pattern in &command_injection {
        for ip in &attack_ips {
            let req = format!("GET /ping?host=127.0.0.1{} HTTP/1.1", pattern);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // Sensitive access
    for path in &sensitive_access {
        for ip in &attack_ips {
            let req = format!("GET {} HTTP/1.1", path);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // SSRF
    for target in &ssrf {
        for ip in &attack_ips {
            let req = format!("GET /fetch?url=http://{}:8080/admin HTTP/1.1", target);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // LDAP
    for pattern in &ldap_injection {
        for ip in &attack_ips {
            let req = format!("GET /users?name={} HTTP/1.1", pattern);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // XXE
    for pattern in &xxe {
        for ip in &attack_ips {
            let req = format!("POST /xml HTTP/1.1 body={}", pattern);
            threat_pool.push(encode_log(ip, &req));
        }
    }
    // HTTP anomalies
    for anomaly in &http_anomalies {
        for ip in &attack_ips {
            let req = format!("HTTP_ANOMALY {}", anomaly);
            threat_pool.push(encode_log(ip, &req));
        }
    }

    // Combine: 90% non-threat, 10% threat (but we'll sample from all combined later)
    // For simplicity, combine all into one pool with appropriate weights.
    // We'll create two separate pools and choose with random.
    // But to keep random index simple, we create a combined vector and a separate distribution? We'll just use three vectors and a random choice.
    let non_threat_pool: Vec<Vec<u8>> = normal_pool
        .into_iter()
        .chain(auth_pool.into_iter())
        .collect();
    let threat_pool = threat_pool;

    // Connect
    let mut stream = TcpStream::connect((host.as_str(), port)).expect("connect");
    stream.set_nodelay(true).ok();

    // Simple xorshift RNG
    let mut rng_state = 0x12345678u64;
    let mut rand_usize = move || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state as usize
    };

    let mut sent = 0u64;
    let start = Instant::now();
    let mut next_report = start + Duration::from_secs(1);

    // Preallocate batch buffer
    let mut batch = Vec::with_capacity(BATCH_SIZE * 256); // estimate average frame size ~100 bytes

    loop {
        batch.clear();
        for _ in 0..BATCH_SIZE {
            // 90% non-threat, 10% threat
            if rand_usize() % 100 < 90 {
                let idx = rand_usize() % non_threat_pool.len();
                batch.extend_from_slice(&non_threat_pool[idx]);
            } else {
                let idx = rand_usize() % threat_pool.len();
                batch.extend_from_slice(&threat_pool[idx]);
            }
        }
        stream.write_all(&batch).expect("write");
        sent += BATCH_SIZE as u64;

        // Rate control
        if rate > 0.0 {
            let expected_elapsed = sent as f64 / rate;
            let actual_elapsed = start.elapsed().as_secs_f64();
            if actual_elapsed < expected_elapsed {
                std::thread::sleep(Duration::from_secs_f64(expected_elapsed - actual_elapsed));
            }
        }

        // Report every second
        let now = Instant::now();
        if now >= next_report {
            let elapsed = now.duration_since(start).as_secs_f64();
            println!("logs={} | rate={:.0}/sec", sent, sent as f64 / elapsed);
            next_report = now + Duration::from_secs(1);
        }
    }
}
