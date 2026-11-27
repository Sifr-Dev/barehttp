//! sifr-serve — zero-dependency static file HTTP/1.1 server.
//!   sifr-serve [root] [--port N]   (default: cwd, port 8080)
//! Features: GET/HEAD, directory index.html, MIME by extension, path
//! traversal protection (canonicalized root), Last-Modified + If-Modified-Since
//! → 304, correct 400/403/404/405/413/431. Request heads are read
//! incrementally up to their CRLFCRLF terminator, so a head split across TCP
//! segments is parsed whole instead of being answered from one partial read.
//! No crates, no async — thread per connection.
use std::fs;
use std::io::{Read, Write};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Hard limit on the request head — request line, header fields and the
/// terminating CRLFCRLF. Reading stops at the terminator, so body bytes are
/// never treated as headers, and a peer that never terminates its head is cut
/// off here instead of growing the buffer without bound.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Largest declared request body the server will acknowledge. Bodies are never
/// read (the response is sent and the connection closed), so this only bounds
/// which framing declarations are accepted before answering 413.
const MAX_BODY_BYTES: u64 = 64 * 1024;

/// Bytes requested from the socket per read.
const READ_CHUNK: usize = 4096;

/// How long one read may block while the head is still incomplete. Bounds the
/// time a stalled client can pin a worker thread; the byte limit bounds memory.
const HEAD_READ_TIMEOUT: Duration = Duration::from_secs(10);

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
    // 1970-01-01 (day 0) was a Thursday, so the weekday is z mod 7. Adding an
    // offset here shifts every emitted date onto the wrong day name.
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(((z % 7) + 7) % 7) as usize];
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
    /// Value of the `Content-Length` header, when the request declared one. The
    /// server never reads request bodies (it answers and closes), but an
    /// unparsable, contradictory or oversized declaration is still a framing
    /// error and must be refused rather than ignored.
    content_length: Option<u64>,
}

/// Why a request head could not be turned into a [`Request`].
#[derive(Debug, PartialEq, Eq)]
enum RequestError {
    /// Structurally invalid: bad request line, non-UTF-8 bytes, bad or
    /// contradictory `Content-Length`.
    Malformed,
    /// Valid HTTP we deliberately do not implement: a transfer coding we would
    /// not decode, so the body cannot be framed.
    UnsupportedTransferEncoding,
}

/// Read a complete request head — request line + header fields + terminating
/// CRLFCRLF — from `reader`, in bounded increments.
///
/// One `read()` is not a message: TCP may split or coalesce arbitrarily, so a
/// head is only parsed once its terminator has actually arrived. Bytes after
/// the terminator (a request body) are never returned as headers, and the head
/// may not grow past [`MAX_HEAD_BYTES`]; the over-limit case is reported
/// distinctly so the caller can answer 431 instead of reading forever.
#[derive(Debug, PartialEq, Eq)]
enum HeadRead {
    /// The head, truncated exactly through its CRLFCRLF terminator.
    Complete(Vec<u8>),
    /// No terminator arrived before the byte limit was reached.
    TooLarge,
    /// The reader timed out with an incomplete head.
    TimedOut,
    /// The peer closed (or the read failed) before the terminator. `buffered`
    /// records whether any bytes of the head had arrived: half a head deserves a
    /// 400, while an immediately-closed idle connection deserves silence.
    Incomplete { buffered: bool },
}

fn find_head_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// Read until the request head is terminated, the byte limit is hit, the peer
/// closes, or a read error/timeout occurs. At most [`MAX_HEAD_BYTES`] bytes are
/// ever buffered, so a client cannot grow this allocation without bound.
fn read_request_head<R: Read>(reader: &mut R) -> HeadRead {
    let mut head: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        // RFC 7230 §3.5: a server SHOULD ignore at least one empty line before
        // the request-line. Leading CRLFs are dropped only while the head still
        // starts with them, so no header or body byte is ever dropped.
        while head.starts_with(b"\r\n") {
            head.drain(..2);
        }
        if let Some(end) = find_head_terminator(&head) {
            head.truncate(end);
            return HeadRead::Complete(head);
        }
        if head.len() >= MAX_HEAD_BYTES {
            return HeadRead::TooLarge;
        }
        let want = READ_CHUNK.min(MAX_HEAD_BYTES - head.len());
        match reader.read(&mut chunk[..want]) {
            Ok(0) => return HeadRead::Incomplete { buffered: !head.is_empty() },
            Ok(n) => head.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                return HeadRead::TimedOut
            }
            Err(_) => return HeadRead::Incomplete { buffered: !head.is_empty() },
        }
    }
}

fn parse_request_checked(raw: &[u8]) -> Result<Request, RequestError> {
    let text = std::str::from_utf8(raw).map_err(|_| RequestError::Malformed)?;
    let mut lines = text.split("\r\n");
    let req_line = lines.next().ok_or(RequestError::Malformed)?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().ok_or(RequestError::Malformed)?.to_string();
    let raw_path = parts.next().ok_or(RequestError::Malformed)?.to_string();
    let version = parts.next().ok_or(RequestError::Malformed)?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestError::Malformed);
    }
    let mut if_mod = None;
    let mut content_length: Option<u64> = None;
    let mut saw_transfer_encoding = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let name = k.trim();
        let value = v.trim();
        if name.eq_ignore_ascii_case("if-modified-since") {
            if_mod = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            // Content-Length is a nonempty sequence of decimal digits. Reject
            // every repeated field, even when its values agree: accepting only
            // selected duplicates makes this parser's framing differ from
            // stricter peers. Transfer-Encoding and Content-Length together
            // are always ambiguous, regardless of their order.
            if saw_transfer_encoding || content_length.is_some() || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(RequestError::Malformed);
            }
            content_length = Some(value.parse().map_err(|_| RequestError::Malformed)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // Multiple transfer-coding fields, or a coding combined with
            // Content-Length, are refused. Identity is the only coding this
            // server can accept without reading and decoding a body.
            if saw_transfer_encoding || content_length.is_some() {
                return Err(RequestError::Malformed);
            }
            saw_transfer_encoding = true;
            if !value.eq_ignore_ascii_case("identity") {
                return Err(RequestError::UnsupportedTransferEncoding);
            }
        }
    }
    Ok(Request { method, path: raw_path, if_modified_since: if_mod, content_length })
}

#[cfg(test)]
fn parse_request(raw: &[u8]) -> Option<Request> {
    parse_request_checked(raw).ok()
}

/// Status to return for a head whose declared body framing is unacceptable, if
/// any. The body itself is never read or buffered.
fn framing_status(req: &Request) -> Option<(u16, &'static str, &'static [u8])> {
    match req.content_length {
        Some(len) if len > MAX_BODY_BYTES => Some((413, "Payload Too Large", b"413 payload too large\n")),
        _ => None,
    }
}

/// Serialize a complete response. Split out from the socket write so the framing
/// (status line, header order, Content-Length, HEAD body suppression) is a pure
/// function the test harness can assert on byte for byte.
fn render(status: u16, reason: &str, headers: &[(String, String)], body: &[u8], head_only: bool) -> Vec<u8> {
    let mut resp = format!("HTTP/1.1 {status} {reason}\r\n");
    resp.push_str("Connection: close\r\n");
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut out = resp.into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    out
}

fn send(stream: &mut TcpStream, status: u16, reason: &str, headers: &[(String, String)], body: &[u8], head_only: bool) -> io::Result<()> {
    stream.write_all(&render(status, reason, headers, body, head_only))
}

/// The one header every plain-text error body is served with.
fn text_plain_headers() -> Vec<(String, String)> {
    vec![("Content-Type".to_string(), "text/plain".to_string())]
}

/// Map a request path onto a real file inside `root`, or the status to return.
/// Query strings are stripped, percent escapes are decoded, and the result is
/// canonicalized so `..` and symlinks cannot escape the served root. Directory
/// requests resolve to `index.html`. Extracted from `handle` so the traversal
/// rules can be tested against a temporary directory without a socket.
fn resolve_target(root: &Path, raw_path: &str) -> Result<PathBuf, u16> {
    let path_part = raw_path.split('?').next().unwrap_or("/");
    let decoded = percent_decode(path_part);
    let rel = decoded.trim_start_matches('/');
    let candidate = root.join(rel);
    let canonical = match candidate.canonicalize() {
        Ok(c) => c,
        Err(_) => return Err(404),
    };
    // Path::starts_with compares whole components, so /srv/web does not match
    // a sibling /srv/web-evil, and canonicalize has already resolved symlinks.
    if !canonical.starts_with(root) {
        return Err(403);
    }
    let mut file_path = canonical;
    if file_path.is_dir() {
        file_path = file_path.join("index.html");
        if !file_path.exists() {
            return Err(404);
        }
    }
    Ok(file_path)
}

fn handle(mut stream: TcpStream, root: &Path) {
    // Bound how long an incomplete head may block, so a silent peer cannot pin
    // a worker thread indefinitely. A timeout mid-head is answered as a 400.
    let _ = stream.set_read_timeout(Some(HEAD_READ_TIMEOUT));
    let head = match read_request_head(&mut stream) {
        HeadRead::Complete(bytes) => bytes,
        HeadRead::TooLarge => {
            let _ = send(&mut stream, 431, "Request Header Fields Too Large", &text_plain_headers(), b"431 request header fields too large\n", false);
            return;
        }
        HeadRead::TimedOut => {
            // Half a head arrived and the peer stalled: answer 400 rather than
            // silently dropping the connection.
            let _ = send(&mut stream, 400, "Bad Request", &text_plain_headers(), b"400 bad request\n", false);
            return;
        }
        // EOF before the terminator: half a head still deserves a 400 (the peer
        // may be half-closing), while a connection that sent nothing at all is
        // closed quietly.
        HeadRead::Incomplete { buffered: true } => {
            let _ = send(&mut stream, 400, "Bad Request", &text_plain_headers(), b"400 bad request\n", false);
            return;
        }
        HeadRead::Incomplete { buffered: false } => return,
    };
    let req = match parse_request_checked(&head) {
        Ok(req) => req,
        // An unsupported transfer coding cannot be framed, so it is refused the
        // same way as any other unsatisfiable head.
        Err(RequestError::UnsupportedTransferEncoding) | Err(RequestError::Malformed) => {
            let _ = send(&mut stream, 400, "Bad Request", &text_plain_headers(), b"400 bad request\n", false);
            return;
        }
    };
    let head_only = req.method == "HEAD";
    if req.method != "GET" && req.method != "HEAD" {
        let _ = send(&mut stream, 405, "Method Not Allowed", &[("Allow".into(), "GET, HEAD".into()), ("Content-Type".into(), "text/plain".into())], b"405 method not allowed\n", head_only);
        return;
    }
    // The body is never read, so the only thing to enforce is whether its
    // declared framing is acceptable at all.
    if let Some((status, reason, body)) = framing_status(&req) {
        let _ = send(&mut stream, status, reason, &text_plain_headers(), body, head_only);
        return;
    }
    let file_path = match resolve_target(root, &req.path) {
        Ok(path) => path,
        Err(404) => {
            let _ = send(&mut stream, 404, "Not Found", &[("Content-Type".into(), "text/plain".into())], b"404 not found\n", head_only);
            return;
        }
        Err(_) => {
            let _ = send(&mut stream, 403, "Forbidden", &[("Content-Type".into(), "text/plain".into())], b"403 forbidden\n", head_only);
            return;
        }
    };
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
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
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
    for stream in listener.incoming().flatten() {
        let root = root_path.clone();
        std::thread::spawn(move || handle(stream, &root));
    }
}

#[cfg(test)]
mod verification {
    //! Deterministic checks over the real request parser, date formatter, MIME
    //! table, percent decoder, response renderer and traversal guard.
    //! Everything here is offline and needs no fixtures except a temporary
    //! directory that the test creates and removes itself.

    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_root(tag: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "sifr-serve-test-{}-{tag}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn req(raw: &str) -> Option<Request> {
        parse_request(raw.as_bytes())
    }

    // ---- request line and headers -------------------------------------------

    #[test]
    fn parses_get_with_version_and_headers() {
        let r = req("GET /style.css HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/style.css");
        assert_eq!(r.if_modified_since.as_deref(), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
    }

    #[test]
    fn header_name_and_value_are_trimmed_and_case_insensitive() {
        let r = req("GET / HTTP/1.1\r\nif-MODIFIED-since:   Tue, 24 Nov 2026 10:00:00 GMT   \r\n\r\n").unwrap();
        assert_eq!(r.if_modified_since.as_deref(), Some("Tue, 24 Nov 2026 10:00:00 GMT"));
    }

    #[test]
    fn accepts_http_1_0_and_1_1_only() {
        assert!(req("GET / HTTP/1.0\r\n\r\n").is_some());
        assert!(req("GET / HTTP/1.1\r\n\r\n").is_some());
        assert!(req("GET / HTTP/2.0\r\n\r\n").is_none());
        assert!(req("GET / HTTP/0.9\r\n\r\n").is_none());
        // A missing third token is malformed, not a default version.
        assert!(req("GET /\r\n\r\n").is_none());
        assert!(req("GET\r\n\r\n").is_none());
    }

    #[test]
    fn rejects_non_utf8_and_empty_input() {
        assert!(parse_request(b"").is_none());
        assert!(parse_request(b"GET / HTTP/1.1\r\n\r\n\xff").is_none());
    }

    #[test]
    fn header_scan_stops_at_the_blank_line() {
        // A header after the terminator is part of the body and must not be read
        // as a request header.
        let r = req("GET / HTTP/1.1\r\n\r\nIf-Modified-Since: Tue, 24 Nov 2026 10:00:00 GMT").unwrap();
        assert_eq!(r.if_modified_since, None);
    }

    #[test]
    fn absolute_path_is_preserved_verbatim() {
        // resolve_target is what strips the query string, not the parser.
        let r = req("GET /a/b.txt?x=1 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.path, "/a/b.txt?x=1");
    }

    #[test]
    fn method_is_case_sensitive_by_design() {
        let r = req("get / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.method, "get");
    }

    // ---- date formatting ----------------------------------------------------

    #[test]
    fn formats_known_epoch_instants() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(86_400), "Fri, 02 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(http_date(1_000_000_000), "Sun, 09 Sep 2001 01:46:40 GMT");
        assert_eq!(http_date(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
        assert_eq!(http_date(4_102_444_800), "Fri, 01 Jan 2100 00:00:00 GMT");
        assert_eq!(http_date(253_402_300_799), "Fri, 31 Dec 9999 23:59:59 GMT");
    }

    #[test]
    fn weekday_matches_the_calendar_date() {
        // Regression: the weekday table was indexed with an extra +4 offset,
        // so every Last-Modified header named the wrong day. A correctly
        // formatted If-Modified-Since from a real client then never matched and
        // 304 responses were unreachable.
        // 1970-01-01 was a Thursday, and each following day advances by one.
        let sequence = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        for day in 0..14u64 {
            let stamp = http_date(day * 86_400);
            let expected = sequence[(day % 7) as usize];
            assert!(
                stamp.starts_with(expected),
                "day {day} should start with {expected}, got {stamp}"
            );
        }
        // Specific real dates, verified against the civil calendar.
        assert!(http_date(1_767_225_600).starts_with("Thu")); // 2026-01-01
        assert!(http_date(1_763_942_400).starts_with("Mon")); // 2025-11-24
        assert!(http_date(1_709_164_800).starts_with("Thu")); // 2024-02-29
        assert!(http_date(1_614_556_800).starts_with("Mon")); // 2021-03-01
    }

    #[test]
    fn civil_from_days_handles_leap_years_and_century_rules() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        // 2000 was a leap year; 1900 (negative day count) was not.
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(2_932_896), (9999, 12, 31));
    }

    #[test]
    fn date_output_is_always_fixed_width() {
        for secs in [0u64, 1, 59, 3_600, 86_399, 1_234_567_890] {
            let stamp = http_date(secs);
            assert_eq!(stamp.len(), 29, "unexpected width: {stamp}");
            assert!(stamp.ends_with(" GMT"));
            assert_eq!(&stamp[3..5], ", ");
        }
    }

    // ---- MIME table ---------------------------------------------------------

    #[test]
    fn maps_extensions_to_content_types() {
        let cases = [
            ("a.html", "text/html; charset=utf-8"),
            ("a.htm", "text/html; charset=utf-8"),
            ("a.css", "text/css; charset=utf-8"),
            ("a.js", "text/javascript; charset=utf-8"),
            ("a.mjs", "text/javascript; charset=utf-8"),
            ("a.json", "application/json"),
            ("a.md", "text/markdown; charset=utf-8"),
            ("a.txt", "text/plain; charset=utf-8"),
            ("a.png", "image/png"),
            ("a.jpg", "image/jpeg"),
            ("a.jpeg", "image/jpeg"),
            ("a.gif", "image/gif"),
            ("a.svg", "image/svg+xml"),
            ("a.ico", "image/x-icon"),
            ("a.pdf", "application/pdf"),
            ("a.wasm", "application/wasm"),
            ("a.wav", "audio/wav"),
            ("a.flac", "audio/flac"),
            ("a.xml", "application/xml"),
        ];
        for (name, expected) in cases {
            assert_eq!(mime_type(Path::new(name)), expected, "for {name}");
        }
        // Unknown, missing and case-varied extensions fall back to octet-stream.
        assert_eq!(mime_type(Path::new("a.bin")), "application/octet-stream");
        assert_eq!(mime_type(Path::new("Makefile")), "application/octet-stream");
        assert_eq!(mime_type(Path::new("a.HTML")), "application/octet-stream");
        assert_eq!(mime_type(Path::new("a.")), "application/octet-stream");
    }

    // ---- percent decoding ---------------------------------------------------

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(percent_decode("/a%20b"), "/a b");
        assert_eq!(percent_decode("%2e%2e%2f"), "../");
        assert_eq!(percent_decode("%2E%2E"), "..");
        assert_eq!(percent_decode("%41%42%43"), "ABC");
        assert_eq!(percent_decode("a%00b"), "a\0b");
    }

    #[test]
    fn leaves_malformed_escapes_alone() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%%41"), "%A");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode(""), "");
    }

    #[test]
    fn decoded_bytes_are_lossy_utf8_not_a_panic() {
        // %FF alone is not valid UTF-8; decoding must not panic.
        let out = percent_decode("%FF");
        assert_eq!(out, "\u{FFFD}");
    }

    // ---- response framing ---------------------------------------------------

    #[test]
    fn renders_status_headers_and_content_length() {
        let headers = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Last-Modified".to_string(), "Thu, 01 Jan 1970 00:00:00 GMT".to_string()),
        ];
        let out = render(200, "OK", &headers, b"hello", false);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn head_suppresses_the_body_but_keeps_its_length() {
        let out = render(200, "OK", &[], b"hello", true);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(!text.contains("hello"));
    }

    #[test]
    fn error_responses_report_their_body_length() {
        for (status, reason, body) in [
            (400u16, "Bad Request", &b"400 bad request\n"[..]),
            (404, "Not Found", &b"404 not found\n"[..]),
            (405, "Method Not Allowed", &b"405 method not allowed\n"[..]),
        ] {
            let out = render(status, reason, &[], body, false);
            let text = String::from_utf8(out).unwrap();
            assert!(text.starts_with(&format!("HTTP/1.1 {status} {reason}\r\n")));
            assert!(text.contains(&format!("Content-Length: {}\r\n", body.len())));
        }
    }

    #[test]
    fn empty_body_still_has_a_zero_length_header() {
        let out = render(304, "Not Modified", &[], b"", false);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    // ---- path resolution and traversal --------------------------------------

    #[test]
    fn serves_a_file_inside_the_root() {
        let root = temp_root("serve");
        fs::write(root.join("a.txt"), b"hi").unwrap();
        let canonical_root = root.canonicalize().unwrap();
        let resolved = resolve_target(&canonical_root, "/a.txt").unwrap();
        assert_eq!(resolved, canonical_root.join("a.txt"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn directory_request_resolves_to_index_html() {
        let root = temp_root("index");
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/index.html"), b"<h1>x</h1>").unwrap();
        let canonical_root = root.canonicalize().unwrap();
        let resolved = resolve_target(&canonical_root, "/sub/").unwrap();
        assert_eq!(resolved, canonical_root.join("sub/index.html"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn directory_without_index_is_not_found() {
        let root = temp_root("noindex");
        fs::create_dir(root.join("empty")).unwrap();
        let canonical_root = root.canonicalize().unwrap();
        assert_eq!(resolve_target(&canonical_root, "/empty/"), Err(404));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn missing_file_is_not_found() {
        let root = temp_root("missing");
        let canonical_root = root.canonicalize().unwrap();
        assert_eq!(resolve_target(&canonical_root, "/nope.txt"), Err(404));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn query_string_is_ignored() {
        let root = temp_root("query");
        fs::write(root.join("a.txt"), b"hi").unwrap();
        let canonical_root = root.canonicalize().unwrap();
        let resolved = resolve_target(&canonical_root, "/a.txt?cache=1").unwrap();
        assert_eq!(resolved, canonical_root.join("a.txt"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn traversal_out_of_the_root_is_rejected() {
        let root = temp_root("traversal");
        let canonical_root = root.canonicalize().unwrap();
        let outside = temp_root("outside");
        fs::write(outside.join("secret.txt"), b"SECRET").unwrap();
        let outside_name = outside.file_name().unwrap().to_str().unwrap().to_string();
        let attempt = format!("/../{outside_name}/secret.txt");
        // Whether the platform reports 403 or 404, the file outside must not be
        // reachable; the resolved path may never be the secret.
        let result = resolve_target(&canonical_root, &attempt);
        assert!(
            matches!(result, Err(403) | Err(404)),
            "escaped the root: {result:?}"
        );
        // The percent-encoded form of the same attempt must fail identically.
        let encoded = format!("/%2e%2e%2f{outside_name}%2fsecret.txt");
        let result = resolve_target(&canonical_root, &encoded);
        assert!(
            matches!(result, Err(403) | Err(404)),
            "encoded form escaped the root: {result:?}"
        );
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn sibling_directory_with_shared_prefix_is_rejected() {
        // "web-evil" starts with "web" as bytes but is not inside "web".
        let base = temp_root("prefix");
        let served = base.join("web");
        let sibling = base.join("web-evil");
        fs::create_dir_all(&served).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("secret.txt"), b"SECRET").unwrap();
        let canonical_root = served.canonicalize().unwrap();
        let result = resolve_target(&canonical_root, "/../web-evil/secret.txt");
        assert!(matches!(result, Err(403) | Err(404)), "got {result:?}");
        fs::remove_dir_all(&base).unwrap();
    }

    // ---- end-to-end over a real loopback socket -----------------------------

    /// One bounded end-to-end exchange against the real handler on 127.0.0.1.
    /// No fixture server is left running: the listener is dropped at the end of
    /// the test and the request has a read timeout.
    fn one_shot(root: &Path, request: &str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let root = root.to_path_buf();
        let handle_thread = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle(stream, &root);
            }
        });
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        // Join the bytes we know are coming; the handler closes the connection.
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            response.push_str(&line);
            line.clear();
        }
        handle_thread.join().unwrap();
        response
    }

    #[test]
    fn end_to_end_get_head_and_errors() {
        let root = temp_root("e2e");
        fs::write(root.join("a.txt"), b"hello world").unwrap();
        let canonical_root = root.canonicalize().unwrap();

        let get = one_shot(&canonical_root, "GET /a.txt HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(get.starts_with("HTTP/1.1 200 OK"), "{get}");
        assert!(get.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(get.contains("Content-Length: 11"));
        assert!(get.contains("Last-Modified: "));
        assert!(get.ends_with("hello world"));

        let head = one_shot(&canonical_root, "HEAD /a.txt HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert!(head.contains("Content-Length: 11"));
        assert!(!head.contains("hello world"));

        let missing = one_shot(&canonical_root, "GET /nope.txt HTTP/1.1\r\n\r\n");
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"), "{missing}");

        let post = one_shot(&canonical_root, "POST /a.txt HTTP/1.1\r\n\r\n");
        assert!(post.starts_with("HTTP/1.1 405 Method Not Allowed"), "{post}");
        assert!(post.contains("Allow: GET, HEAD"));

        let bad = one_shot(&canonical_root, "NONSENSE\r\n\r\n");
        assert!(bad.starts_with("HTTP/1.1 400 Bad Request"), "{bad}");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn end_to_end_conditional_request_matches_its_own_last_modified() {
        // The bug this guards: a wrong weekday in Last-Modified made a client's
        // correct If-Modified-Since never match, so 304 was unreachable.
        let root = temp_root("cond");
        fs::write(root.join("a.txt"), b"hello").unwrap();
        let canonical_root = root.canonicalize().unwrap();

        let first = one_shot(&canonical_root, "GET /a.txt HTTP/1.1\r\n\r\n");
        let last_mod = first
            .lines()
            .find_map(|l| l.strip_prefix("Last-Modified: "))
            .expect("Last-Modified header")
            .trim()
            .to_string();
        assert!(
            last_mod.starts_with(['M', 'T', 'W', 'F', 'S', 'S']),
            "unexpected date: {last_mod}"
        );

        let conditional = format!(
            "GET /a.txt HTTP/1.1\r\nIf-Modified-Since: {last_mod}\r\n\r\n"
        );
        let second = one_shot(&canonical_root, &conditional);
        assert!(
            second.starts_with("HTTP/1.1 304 Not Modified"),
            "conditional request did not return 304: {second}"
        );
        fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(test)]
mod loopback_framing {
    //! Request-framing regressions over real TCP sockets. These tests use the
    //! production handler directly, with a fresh ephemeral listener per case.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    // Keep this protocol-level expectation independent so the same module can
    // also be run against the pre-incremental-reader implementation.
    const HEAD_LIMIT: usize = 16 * 1024;

    fn test_root(tag: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "sifr-serve-framing-{}-{tag}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"framing test body").unwrap();
        dir
    }

    /// Run one client exchange and return every response byte through EOF.
    fn exchange<F>(root: &Path, send_request: F) -> Vec<u8>
    where
        F: FnOnce(&mut TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let root = root.to_path_buf();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream, &root);
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        send_request(&mut client);
        let mut response = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            match client.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&chunk[..n]),
                // The handler closes as soon as an oversized head is rejected.
                // If excess request bytes are still queued, Linux reports that
                // close as a reset; response bytes read before it remain valid.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset && !response.is_empty() => break,
                Err(e) => panic!("reading loopback response failed: {e}"),
            }
        }
        server.join().unwrap();
        response
    }

    fn request(headers: &str) -> String {
        format!("GET /a.txt HTTP/1.1\r\nHost: loopback\r\n{headers}\r\n")
    }

    fn one_request(root: &Path, raw: String) -> Vec<u8> {
        exchange(root, move |client| {
            // A peer may already have closed its write side after sending an
            // over-limit stream, so an EPIPE here must not hide its response.
            let _ = client.write_all(raw.as_bytes());
            let _ = client.shutdown(std::net::Shutdown::Write);
        })
    }

    fn status_line(response: &[u8]) -> String {
        std::str::from_utf8(response)
            .unwrap()
            .split("\r\n")
            .next()
            .unwrap()
            .to_string()
    }

    fn assert_status(response: &[u8], expected: &str) {
        assert_eq!(status_line(response), expected, "response: {}", String::from_utf8_lossy(response));
    }

    #[test]
    fn headers_and_delimiters_fragmented_across_many_writes_are_served() {
        let root = test_root("fragmented");
        let canonical_root = root.canonicalize().unwrap();
        let raw = request("X-First: one\r\nX-Second: two\r\nX-Third: three\r\n");
        let write_count = raw.len();
        let response = exchange(&canonical_root, move |client| {
            client.set_nodelay(true).unwrap();
            // One byte per write deliberately splits every CRLF, including the
            // four-byte head terminator, rather than relying on read chunking.
            for &byte in raw.as_bytes() {
                if client.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = client.shutdown(std::net::Shutdown::Write);
        });
        assert!(write_count > 80, "test did not exercise many writes");
        assert_status(&response, "HTTP/1.1 200 OK");
        assert!(response.ends_with(b"framing test body"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn coalesced_requests_only_serve_the_first_complete_head() {
        let root = test_root("coalesced");
        let canonical_root = root.canonicalize().unwrap();
        let mut raw = request("");
        raw.push_str("GET /a.txt HTTP/1.1\r\nHost: second\r\nIf-Modified-Since: invalid\r\n\r\n");
        let response = one_request(&canonical_root, raw);
        let text = String::from_utf8(response).unwrap();
        assert_status(text.as_bytes(), "HTTP/1.1 200 OK");
        assert_eq!(text.matches("HTTP/1.1 ").count(), 1, "{text}");
        assert_eq!(text.matches("framing test body").count(), 1, "{text}");
        assert!(text.contains("Connection: close\r\n"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn malformed_content_length_is_rejected() {
        let root = test_root("bad-length");
        let canonical_root = root.canonicalize().unwrap();
        for value in ["", "abc", "1, 1", "+1", "-1", "18446744073709551616"] {
            let response = one_request(
                &canonical_root,
                request(&format!("Content-Length: {value}\r\n")),
            );
            assert_status(&response, "HTTP/1.1 400 Bad Request");
        }
        // A single decimal declaration retains the existing accepted behavior.
        let response = one_request(&canonical_root, request("Content-Length: 0\r\n"));
        assert_status(&response, "HTTP/1.1 200 OK");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn duplicate_or_conflicting_content_lengths_are_rejected() {
        let root = test_root("duplicate-length");
        let canonical_root = root.canonicalize().unwrap();
        for headers in [
            "Content-Length: 0\r\nContent-Length: 1\r\n",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Content-Length: 01\r\nContent-Length: 1\r\n",
        ] {
            let response = one_request(&canonical_root, request(headers));
            assert_status(&response, "HTTP/1.1 400 Bad Request");
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn transfer_encoding_conflicts_and_duplicates_are_rejected() {
        let root = test_root("transfer-encoding");
        let canonical_root = root.canonicalize().unwrap();
        for headers in [
            "Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: identity\r\nTransfer-Encoding: identity\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: identity\r\nContent-Length: 0\r\n",
            "Content-Length: 0\r\nTransfer-Encoding: identity\r\n",
        ] {
            let response = one_request(&canonical_root, request(headers));
            assert_status(&response, "HTTP/1.1 400 Bad Request");
        }
        let response = one_request(&canonical_root, request("Transfer-Encoding: identity\r\n"));
        assert_status(&response, "HTTP/1.1 200 OK");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn eof_before_the_complete_delimiter_is_rejected() {
        let root = test_root("incomplete-eof");
        let canonical_root = root.canonicalize().unwrap();
        for raw in [
            "GET /a.txt HTTP/1.1\r\nHost: loopback\r\nX-Incomplete: yes\r\n",
            "GET /a.txt HTTP/1.1\r\nHost: loopback\r\n\r",
        ] {
            let response = one_request(&canonical_root, raw.to_string());
            assert_status(&response, "HTTP/1.1 400 Bad Request");
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn over_limit_socket_head_returns_431() {
        let root = test_root("large-head");
        let canonical_root = root.canonicalize().unwrap();
        let mut raw = b"GET /a.txt HTTP/1.1\r\nHost: loopback\r\nX-Fill: ".to_vec();
        raw.resize(HEAD_LIMIT + 4096, b'x');
        let response = one_request(&canonical_root, raw.into_iter().map(char::from).collect());
        assert_status(&response, "HTTP/1.1 431 Request Header Fields Too Large");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn declared_body_over_the_existing_limit_returns_413() {
        let root = test_root("large-body");
        let canonical_root = root.canonicalize().unwrap();
        let response = one_request(
            &canonical_root,
            request("Content-Length: 65537\r\n"),
        );
        assert_status(&response, "HTTP/1.1 413 Payload Too Large");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unterminated_reader_input_stops_at_the_buffer_limit() {
        #[derive(Default)]
        struct Endless {
            bytes_read: usize,
            calls: usize,
        }

        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                assert!(!buf.is_empty());
                self.calls += 1;
                self.bytes_read += buf.len();
                buf.fill(b'x');
                Ok(buf.len())
            }
        }

        let mut reader = Endless::default();
        assert_eq!(read_request_head(&mut reader), HeadRead::TooLarge);
        assert_eq!(reader.bytes_read, MAX_HEAD_BYTES);
        assert_eq!(reader.calls, MAX_HEAD_BYTES / READ_CHUNK);
        assert_eq!(HEAD_LIMIT, MAX_HEAD_BYTES);
    }
}
