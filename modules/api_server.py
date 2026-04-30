#!/usr/bin/env python3
# Copyright (c) 2024-2026 Jorge Francisco Paredes (irstabyjorge)
# Licensed under dual MIT/Commercial license. See LICENSE and COMMERCIAL_LICENSE.md
"""
AEGIS API Server — REST API exposing all AEGIS capabilities.
Built with http.server (zero external deps). For production, use with FastAPI.
"""

import json, os, sys, re, secrets, stat, time, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, UTC
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis_omni import QByteEngine, SystemAnalyzer, EntropyModule, PredictiveEngine, BLOCKLIST, __version__
from modules.uptime_monitor import run_checks as uptime_checks
from modules.log_analyzer import analyze_system_logs, analyze_aegis_threats
from modules.vuln_scanner import full_scan as vuln_scan
from modules.ioc_scanner import full_scan as ioc_scan
from modules.forensics import full_forensic_capture
from modules.password_audit import full_audit as password_audit
from modules.payload_detector import scan_web_logs as payload_scan
from modules.honeypot import analyze_honeypot_logs


qbyte = QByteEngine()
system = SystemAnalyzer()
entropy_mod = EntropyModule()
predictor = PredictiveEngine()

# ---------------------------------------------------------------------------
# API Token management
# ---------------------------------------------------------------------------
_TOKEN_PATH = Path(__file__).resolve().parent.parent / "brain" / "api_token.txt"


def _load_or_create_token() -> str:
    """Load existing API token or generate a new one (chmod 600)."""
    _TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _TOKEN_PATH.exists():
        return _TOKEN_PATH.read_text().strip()
    token = secrets.token_urlsafe(48)
    _TOKEN_PATH.write_text(token + "\n")
    os.chmod(_TOKEN_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 600
    return token


API_TOKEN: str = _load_or_create_token()

# ---------------------------------------------------------------------------
# Rate limiting — 60 requests / minute per client IP (in-memory)
# ---------------------------------------------------------------------------
_RATE_LIMIT = 60          # max requests
_RATE_WINDOW = 60.0       # window in seconds
_rate_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _is_rate_limited(client_ip: str) -> bool:
    """Return True if *client_ip* has exceeded the rate limit."""
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets[client_ip]
        # Prune timestamps older than the window
        _rate_buckets[client_ip] = bucket = [
            ts for ts in bucket if now - ts < _RATE_WINDOW
        ]
        if len(bucket) >= _RATE_LIMIT:
            return True
        bucket.append(now)
        return False

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")  # loose check; further validated below


def _is_valid_ip(value: str) -> bool:
    """Return True if *value* looks like a valid IPv4 or IPv6 address."""
    if _IPV4_RE.match(value):
        return True
    # Basic IPv6 structural check (1-8 groups of hex, possibly with ::)
    if _IPV6_RE.match(value) and 2 <= len(value) <= 45:
        return True
    return False


class AegisAPIHandler(BaseHTTPRequestHandler):
    # Endpoints that do NOT require authentication
    _PUBLIC_PATHS = frozenset({"/", "/healthz"})

    def _check_auth(self, path: str) -> bool:
        """Return True if the request is authorized. Sends 401 and returns False otherwise."""
        if path in self._PUBLIC_PATHS:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {API_TOKEN}":
            return True
        self._respond(401, {"error": "unauthorized", "message": "Missing or invalid Bearer token in Authorization header"})
        return False

    def do_GET(self):
        path = self.path.split("?")[0]

        # --- Rate limiting (applies to every request, including public) ---
        client_ip = self.client_address[0]
        if _is_rate_limited(client_ip):
            self._respond(429, {"error": "rate_limited", "message": "Max 60 requests per minute. Try again shortly."})
            return

        # --- Authentication ---
        if not self._check_auth(path):
            return

        routes = {
            "/": self._index,
            "/healthz": self._healthz,
            "/api/status": self._status,
            "/api/threats": self._threats,
            "/api/listeners": self._listeners,
            "/api/connections": self._connections,
            "/api/entropy": self._entropy,
            "/api/blocklist": self._blocklist,
            "/api/uptime": self._uptime,
            "/api/logs/analysis": self._log_analysis,
            "/api/logs/threats": self._threat_analysis,
            "/api/predict": self._predict,
            "/api/vuln": self._vuln_scan,
            "/api/ioc": self._ioc_scan,
            "/api/forensics": self._forensics,
            "/api/passwords": self._password_audit,
            "/api/payloads": self._payload_scan,
            "/api/honeypot": self._honeypot_stats,
        }

        handler = routes.get(path)
        if handler:
            handler()
        elif path.startswith("/api/scan/"):
            ip = path.split("/api/scan/")[1]
            if not _is_valid_ip(ip):
                self._respond(400, {"error": "invalid_ip", "message": f"'{ip}' is not a valid IPv4/IPv6 address"})
                return
            self._scan_ip(ip)
        else:
            self._respond(404, {"error": "not_found", "path": path, "endpoints": list(routes.keys())})

    def do_HEAD(self):
        client_ip = self.client_address[0]
        if _is_rate_limited(client_ip):
            self.send_response(429)
            self.end_headers()
            return
        path = self.path.split("?")[0]
        if not self._check_auth(path):
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def _respond(self, code, data):
        body = json.dumps(data, default=str, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Engine", f"AEGIS-QByte22-v{__version__}")
        self.end_headers()
        self.wfile.write(body)

    def _index(self):
        self._respond(200, {
            "service": "AEGIS OMNI-XEON API",
            "version": __version__,
            "engine": "QByte-22",
            "endpoints": [
                "GET /healthz",
                "GET /api/status",
                "GET /api/threats",
                "GET /api/listeners",
                "GET /api/connections",
                "GET /api/scan/<ip>",
                "GET /api/entropy",
                "GET /api/blocklist",
                "GET /api/uptime",
                "GET /api/logs/analysis",
                "GET /api/logs/threats",
                "GET /api/predict",
                "GET /api/vuln",
                "GET /api/ioc",
                "GET /api/forensics",
                "GET /api/passwords",
                "GET /api/payloads",
                "GET /api/honeypot",
            ],
        })

    def _healthz(self):
        self._respond(200, {"status": "ok", "engine": f"QByte-22 v{__version__}", "time": datetime.now(UTC).isoformat()})

    def _status(self):
        self._respond(200, system.status())

    def _threats(self):
        threats = qbyte.scan_live_connections()
        self._respond(200, {
            "threats_found": len(threats),
            "results": [{"ip": t.ip, "score": t.score, "level": t.level, "action": t.action, "signals": t.signals} for t in threats],
        })

    def _listeners(self):
        self._respond(200, {"listeners": qbyte.scan_listeners()})

    def _connections(self):
        import psutil
        conns = []
        for c in psutil.net_connections(kind="inet"):
            if c.raddr:
                proc = None
                try:
                    proc = psutil.Process(c.pid).name() if c.pid else None
                except Exception:
                    pass
                conns.append({
                    "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    "pid": c.pid, "process": proc, "status": c.status,
                })
        self._respond(200, {"connections": conns[:200]})

    def _scan_ip(self, ip):
        threat = qbyte.analyze_ip(ip)
        qbyte.auto_blocklist(threat)
        self._respond(200, {
            "ip": threat.ip, "score": threat.score, "level": threat.level,
            "action": threat.action, "signals": threat.signals,
            "confidence": threat.confidence,
        })

    def _entropy(self):
        self._respond(200, entropy_mod.generate())

    def _blocklist(self):
        self._respond(200, {"blocked_ips": sorted(BLOCKLIST), "count": len(BLOCKLIST)})

    def _uptime(self):
        self._respond(200, uptime_checks())

    def _log_analysis(self):
        self._respond(200, analyze_system_logs())

    def _threat_analysis(self):
        self._respond(200, analyze_aegis_threats())

    def _predict(self):
        self._respond(200, predictor.train_on_history())

    def _vuln_scan(self):
        self._respond(200, vuln_scan())

    def _ioc_scan(self):
        self._respond(200, ioc_scan())

    def _forensics(self):
        self._respond(200, full_forensic_capture())

    def _password_audit(self):
        self._respond(200, password_audit())

    def _payload_scan(self):
        self._respond(200, payload_scan())

    def _honeypot_stats(self):
        self._respond(200, analyze_honeypot_logs())

    def log_message(self, format, *args):
        pass


def main():
    port = int(os.environ.get("AEGIS_PORT", 8443))
    bind = os.environ.get("AEGIS_BIND", "127.0.0.1")
    server = HTTPServer((bind, port), AegisAPIHandler)
    print(f"AEGIS API Server v{__version__} running on http://{bind}:{port}")
    print(f"Endpoints: http://localhost:{port}/")
    print(f"API token: {_TOKEN_PATH}")
    print(f"Rate limit: {_RATE_LIMIT} req/{int(_RATE_WINDOW)}s per IP")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
