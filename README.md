<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
    <img alt="sifr-serve — built from zero" src=".github/banner-light.svg" width="100%">
  </picture>
</p>

# sifr-serve

zero-dependency static file HTTP/1.1 server in Rust. no crates, no
async runtime — thread per connection. built to host real sites, not demos.

```sh
sifr-serve [root] [--port N]   # default: . on 8080
sifr-serve /var/www --port 8090
```

## features

- GET/HEAD with correct 200/400/403/404/405
- `index.html` for directory requests
- MIME by extension (html/css/js/json/md/png/pdf/wasm/wav/flac/…)
- path traversal protection (canonicalized root, `/../../etc/passwd` → 403)
- `Last-Modified` + `If-Modified-Since` → 304
- `Connection: close`, byte-counted `Content-Length`

## verified (this machine, 2026-11-17)

```console
$ sifr-serve /tmp/opencode/webroot --port 8899 &   # 5-second live run
$ curl -si localhost:8899/style.css   → 200 text/css; charset=utf-8, len 45
$ curl -si localhost:8899/test.json   → 200 application/json
$ curl -sI localhost:8899/            → 200, Last-Modified present
$ curl -s -o /dev/null -w '%{http_code}' localhost:8899/nope.txt  → 404
$ curl -s -o /dev/null -w '%{http_code}' --path-as-is 'localhost:8899/../../etc/passwd' → 403
$ curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8899/   → 405
```

## tests

```sh
cargo test            # 28 deterministic tests, ~0.0 s
cargo test --release
```

The suite is offline and needs no fixtures: request parsing (versions,
malformed input, header scanning), HTTP date formatting and the
days-from-civil conversion, the MIME table, percent decoding, response
framing (including HEAD body suppression and Content-Length), path
resolution (`index.html`, query strings, traversal and prefix-sibling
rejection), plus two bounded end-to-end exchanges against the real handler on
a loopback socket bound to port 0.

## license

`MIT` — see `LICENSE`. built from zero.
