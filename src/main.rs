//! sifr-serve — zero-dependency static file HTTP/1.1 server.
//!   sifr-serve [root] [--port N]   (default: cwd, port 8080)
//! Features: GET/HEAD, directory index.html, MIME by extension, path
//! traversal protection (canonicalized root), Last-Modified + If-Modified-Since
//! → 304, correct 400/403/404/405. No crates, no async — thread per connection.
use std::fs;
use std::io::{Read, Write};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

fn mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "md" => "text/markdown; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "xml" => "application/xml",
        _ => "application/octet-stream",
    }
}

fn http_date(secs: u64) -> String {
    // days-from-civil algorithm (no chrono)
    let z = (secs as i64) / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(z);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][((z + 4) % 7 + 7) as usize % 7];
    let mon = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    format!("{wd}, {d:02} {mon} {y:04} {h:02}:{m:02}:{s:02} GMT", mon = mon[(mo - 1) as usize])
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

struct Request {
    method: String,
    path: String,
    if_modified_since: Option<String>,
}

fn parse_request(raw: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_string();
    let raw_path = parts.next()?.to_string();
    let _version = parts.next()?;
    if _version != "HTTP/1.1" && _version != "HTTP/1.0" {
        return None;
    }
    let mut if_mod = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("if-modified-since") {
                if_mod = Some(v.trim().to_string());
            }
        }
    }
    Some(Request { method, path: raw_path, if_modified_since: if_mod })
}

fn send(stream: &mut TcpStream, status: u16, reason: &str, headers: &[(String, String)], body: &[u8], head_only: bool) -> io::Result<()> {
    let mut resp = format!("HTTP/1.1 {status} {reason}\r\n");
    resp.push_str("Connection: close\r\n");
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    stream.write_all(resp.as_bytes())?;
    if !head_only {
        stream.write_all(body)?;
    }
    Ok(())
}

fn handle(mut stream: TcpStream, root: &Path) {
    let mut buf = vec![0u8; 16384];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let Some(req) = parse_request(&buf[..n]) else {
        let _ = send(&mut stream, 400, "Bad Request", &[("Content-Type".into(), "text/plain".into())], b"400 bad request\n", false);
        return;
    };
    let head_only = req.method == "HEAD";
    if req.method != "GET" && req.method != "HEAD" {
        let _ = send(&mut stream, 405, "Method Not Allowed", &[("Allow".into(), "GET, HEAD".into()), ("Content-Type".into(), "text/plain".into())], b"405 method not allowed\n", head_only);
        return;
    }
    // strip query string, normalize, prevent traversal
    let path_part = req.path.split('?').next().unwrap_or("/");
    let decoded = percent_decode(path_part);
    let rel = decoded.trim_start_matches('/');
    let candidate = root.join(rel);
    let canonical = match candidate.canonicalize() {
        Ok(c) => c,
        Err(_) => {
            let _ = send(&mut stream, 404, "Not Found", &[("Content-Type".into(), "text/plain".into())], b"404 not found\n", head_only);
            return;
        }
    };
    if !canonical.starts_with(root) {
        let _ = send(&mut stream, 403, "Forbidden", &[("Content-Type".into(), "text/plain".into())], b"403 forbidden\n", head_only);
        return;
    }
    let mut file_path = canonical;
    if file_path.is_dir() {
        file_path = file_path.join("index.html");
        if !file_path.exists() {
            let _ = send(&mut stream, 404, "Not Found", &[("Content-Type".into(), "text/plain".into())], b"404 not found\n", head_only);
            return;
        }
    }
    let meta = match fs::metadata(&file_path) {
        Ok(m) => m,
        Err(_) => {
            let _ = send(&mut stream, 404, "Not Found", &[("Content-Type".into(), "text/plain".into())], b"404 not found\n", head_only);
            return;
        }
    };
    let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    let last_mod = http_date(mtime);
    if let Some(ims) = &req.if_modified_since {
        if *ims == last_mod {
            let _ = send(&mut stream, 304, "Not Modified", &[("Last-Modified".into(), last_mod)], b"", head_only);
            return;
        }
    }
    let body = match fs::read(&file_path) {
        Ok(b) => b,
        Err(_) => {
            let _ = send(&mut stream, 404, "Not Found", &[("Content-Type".into(), "text/plain".into())], b"404 not found\n", head_only);
            return;
        }
    };
    let _ = send(&mut stream, 200, "OK", &[
        ("Content-Type".into(), mime_type(&file_path).to_string()),
        ("Last-Modified".into(), last_mod),
        ("Cache-Control".into(), "no-cache".into()),
    ], &body, head_only);
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() - 1 + 1 {
            if i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() - 1 {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut root: Option<String> = None;
    let mut port: u16 = 8080;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--port" {
            port = args.get(i + 1).and_then(|p| p.parse().ok()).unwrap_or_else(|| { eprintln!("bad --port"); std::process::exit(2); });
            i += 2;
        } else {
            root = Some(args[i].clone());
            i += 1;
        }
    }
    let root = root.unwrap_or_else(|| ".".to_string());
    let root_path = PathBuf::from(&root).canonicalize().unwrap_or_else(|e| {
        eprintln!("sifr-serve: cannot canonicalize {root}: {e}");
        std::process::exit(2);
    });
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| {
        eprintln!("sifr-serve: bind 127.0.0.1:{port} failed: {e}");
        std::process::exit(1);
    });
    println!("sifr-serve root={} url=http://127.0.0.1:{port}/", root_path.display());
    for stream in listener.incoming() {
        if let Ok(s) = stream {
            let root = root_path.clone();
            std::thread::spawn(move || handle(s, &root));
        }
    }
}
