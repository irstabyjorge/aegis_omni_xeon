#!/usr/bin/env python3
# Copyright (c) 2024-2026 Jorge Francisco Paredes (irstabyjorge)
# Licensed under dual MIT/Commercial license. See LICENSE and COMMERCIAL_LICENSE.md
"""
AEGIS Chat — AI-powered security assistant with advanced desktop GUI.
GPU-accelerated rendering, settings panel, advanced tools, privilege controls.
"""

__version__ = "3.0.0"

import sys, os, json, re, subprocess, threading, time, platform, shutil
from pathlib import Path
from datetime import datetime, UTC

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import tkinter as tk
    from tkinter import scrolledtext, messagebox, font as tkfont, ttk, filedialog
    HAS_TK = True
except ImportError:
    HAS_TK = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from modules.uptime_monitor import run_checks as uptime_checks
from modules.log_analyzer import analyze_system_logs, analyze_aegis_threats
from modules.vuln_scanner import full_scan as vuln_full_scan
from modules.ioc_scanner import full_scan as ioc_full_scan
from modules.forensics import full_forensic_capture, hash_critical_binaries, capture_volatile_state
from modules.password_audit import full_audit as password_full_audit
from modules.payload_detector import scan_web_logs as payload_scan_web
from modules.honeypot import analyze_honeypot_logs

BASE = Path(__file__).resolve().parent
LOGS = BASE / "logs"
BRAIN_DIR = BASE / "brain"
CONFIG_FILE = BRAIN_DIR / "gui_config.json"
LOGS.mkdir(parents=True, exist_ok=True)
BRAIN_DIR.mkdir(parents=True, exist_ok=True)

THEMES = {
    "hacker": {
        "name": "Hacker Green",
        "bg": "#050a05", "bg2": "#0a120a", "header": "#0d1a0d",
        "accent": "#00ff88", "accent2": "#00cc66", "accent_dim": "#004422",
        "text": "#c8e6c9", "text_bright": "#e0ffe0", "text_dim": "#3a5a3a",
        "user_color": "#00bfff", "error": "#ff4444", "warn": "#ffaa00",
        "input_bg": "#0d1a0d", "btn_fg": "#000000",
        "border": "#1a3a1a", "card_bg": "#0a150a",
        "gauge_low": "#00ff88", "gauge_mid": "#ffaa00", "gauge_high": "#ff4444",
    },
    "midnight": {
        "name": "Midnight Blue",
        "bg": "#050510", "bg2": "#0a0a1a", "header": "#0d0d22",
        "accent": "#6688ff", "accent2": "#4466dd", "accent_dim": "#222244",
        "text": "#c8c8e6", "text_bright": "#e0e0ff", "text_dim": "#3a3a5a",
        "user_color": "#ff88cc", "error": "#ff4444", "warn": "#ffaa00",
        "input_bg": "#0d0d22", "btn_fg": "#000000",
        "border": "#1a1a3a", "card_bg": "#0a0a18",
        "gauge_low": "#6688ff", "gauge_mid": "#ffaa00", "gauge_high": "#ff4444",
    },
    "crimson": {
        "name": "Crimson Ops",
        "bg": "#0a0505", "bg2": "#120a0a", "header": "#1a0d0d",
        "accent": "#ff4466", "accent2": "#cc3344", "accent_dim": "#442222",
        "text": "#e6c8c8", "text_bright": "#ffe0e0", "text_dim": "#5a3a3a",
        "user_color": "#44aaff", "error": "#ff4444", "warn": "#ffaa00",
        "input_bg": "#1a0d0d", "btn_fg": "#000000",
        "border": "#3a1a1a", "card_bg": "#150a0a",
        "gauge_low": "#ff4466", "gauge_mid": "#ffaa00", "gauge_high": "#ff4444",
    },
    "stealth": {
        "name": "Stealth Dark",
        "bg": "#0a0a0a", "bg2": "#111111", "header": "#161616",
        "accent": "#aaaaaa", "accent2": "#888888", "accent_dim": "#333333",
        "text": "#cccccc", "text_bright": "#eeeeee", "text_dim": "#444444",
        "user_color": "#88bbee", "error": "#ff4444", "warn": "#ffaa00",
        "input_bg": "#161616", "btn_fg": "#000000",
        "border": "#2a2a2a", "card_bg": "#121212",
        "gauge_low": "#aaaaaa", "gauge_mid": "#ffaa00", "gauge_high": "#ff4444",
    },
}

DEFAULT_CONFIG = {
    "theme": "hacker",
    "font_size": 11,
    "font_family": "Consolas",
    "window_width": 1200,
    "window_height": 800,
    "opacity": 0.95,
    "show_system_stats": True,
    "show_toolbar": True,
    "auto_scroll": True,
    "timestamp_messages": False,
    "privilege_level": "user",
    "max_history": 1000,
    "scan_timeout": 60,
    "enable_animations": True,
    "confirm_destructive": True,
    "log_conversations": True,
    "api_provider": "auto",
}

PRIVILEGE_LEVELS = {
    "user": {
        "label": "Standard User",
        "allowed": ["scan_ip", "vuln_scan", "ioc_scan", "uptime", "log_analysis",
                     "system_info", "disk", "memory", "cpu", "processes", "my_ip",
                     "dns_lookup", "ping", "whois", "kernel", "users", "help",
                     "hashes", "connections", "listening_ports", "routes", "arp",
                     "wifi", "cron", "services", "threat_analysis", "show_config",
                     "honeypot_stats", "password_audit", "payload_scan"],
    },
    "operator": {
        "label": "Security Operator",
        "allowed": "all",
        "except": ["block_ip"],
    },
    "admin": {
        "label": "Administrator",
        "allowed": "all",
    },
}


def _load_config():
    if CONFIG_FILE.exists():
        try:
            saved = json.loads(CONFIG_FILE.read_text())
            cfg = {**DEFAULT_CONFIG, **saved}
            return cfg
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def _save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
        return r.stdout.strip() + ("\n" + r.stderr.strip() if r.stderr.strip() else "")
    except subprocess.TimeoutExpired:
        return "[timed out]"
    except Exception as e:
        return f"[error: {e}]"


def _format_result(data):
    if isinstance(data, dict):
        return json.dumps(data, indent=2, default=str)
    return str(data)


INTENT_MAP = [
    (r"(?:scan|check|analyze)\s+(?:this\s+)?(?:ip|address)\s+(\d+\.\d+\.\d+\.\d+)", "scan_ip"),
    (r"(?:scan|check)\s+(?:for\s+)?vulnerabilit|vuln\s*scan|how\s+(?:secure|safe)\s+is\s+(?:my|this)\s+(?:system|machine|computer)", "vuln_scan"),
    (r"(?:check|scan)\s+(?:for\s+)?(?:compromise|ioc|malware|rootkit|trojan|virus)", "ioc_scan"),
    (r"(?:forensic|evidence|capture\s+state|volatile)", "forensics"),
    (r"(?:password|credential|passwd).*(?:audit|check|scan|weak|strong|policy)", "password_audit"),
    (r"(?:payload|attack|injection|xss|sqli|sql\s+injection|web\s+shell)", "payload_scan"),
    (r"(?:honeypot|decoy|trap).*(?:stat|analyz|result|data)", "honeypot_stats"),
    (r"(?:uptime|service|availability|website|http|site).*(?:check|monitor|status|up|down)", "uptime"),
    (r"(?:log|auth\.log|syslog).*(?:analy|scan|check|review)", "log_analysis"),
    (r"threat.*(?:log|history|analys)", "threat_analysis"),
    (r"(?:hash|integrity|binary|checksum).*(?:check|verify|scan)", "hashes"),
    (r"(?:who\s+is|whois)\s+(\S+)", "whois"),
    (r"(?:lookup|resolve|dns|nslookup|dig)\s+(\S+)", "dns_lookup"),
    (r"(?:ping)\s+(\S+)", "ping"),
    (r"(?:port\s*scan|nmap|scan\s+ports?)\s+(\S+)", "port_scan"),
    (r"(?:trace\s*route|tracepath|tracert)\s+(\S+)", "traceroute"),
    (r"(?:open|listening)\s+ports?|what.*listen|netstat|ss\s", "listening_ports"),
    (r"(?:connection|connected|active\s+connection|network\s+connection)", "connections"),
    (r"(?:process|running|top|what.+running|ps\s)", "processes"),
    (r"(?:firewall|ufw|iptables).*(?:status|check|show|rule)", "firewall"),
    (r"(?:check|show|view)?\s*(?:disk|storage|space|drive)", "disk"),
    (r"(?:disk|storage|space|drive).*(?:usage|check|free|full)", "disk"),
    (r"(?:check|show|view)?\s*(?:memory|ram|swap)", "memory"),
    (r"(?:memory|ram|swap).*(?:usage|check|free)", "memory"),
    (r"(?:check|show|view)?\s*(?:cpu|processor|load)", "cpu"),
    (r"(?:cpu|processor|load).*(?:usage|check|load)", "cpu"),
    (r"(?:system|machine|computer).*(?:info|status|health|overview)", "system_info"),
    (r"(?:user|account|who\s+is\s+logged|w\s|who\b)", "users"),
    (r"(?:ip\s+address|my\s+ip|what.*(?:my|this).*ip)", "my_ip"),
    (r"(?:route|routing\s+table|gateway)", "routes"),
    (r"(?:arp|neighbor|mac\s+address)", "arp"),
    (r"(?:kernel|uname|os\s+version|linux\s+version)", "kernel"),
    (r"(?:cron|scheduled|crontab|job)", "cron"),
    (r"(?:service|systemctl|daemon).*(?:list|status|running|active)", "services"),
    (r"(?:wifi|wireless|wlan|iwconfig)", "wifi"),
    (r"(?:block|ban)\s+(?:ip\s+)?(\d+\.\d+\.\d+\.\d+)", "block_ip"),
    (r"(?:blocklist|blocked|banned).*(?:ip|list|show)", "blocklist"),
    (r"(?:full|complete|everything|all).*(?:audit|scan|check|report)", "full_audit"),
    (r"(?:help|what\s+can\s+you|command|menu|option)", "help"),
    (r"(?:status|health|overview)", "system_info"),
    (r"(?:set\s+key|api\s+key|configure\s+key)", "set_key"),
    (r"(?:config|settings|show\s+config)", "show_config"),
    (r"^(?:hi|hello|hey|sup|yo|greetings|what's up|hola|buenos)\b", "greeting"),
]


def match_intent(msg):
    msg_lower = msg.lower().strip()
    for pattern, intent in INTENT_MAP:
        m = re.search(pattern, msg_lower)
        if m:
            args = [g for g in m.groups() if g] if m.groups() else []
            return intent, args
    return "unknown", []


def execute_intent(intent, args):
    try:
        if intent == "scan_ip":
            ip = args[0] if args else "8.8.8.8"
            from aegis_omni import QByteEngine
            qb = QByteEngine()
            t = qb.analyze_ip(ip)
            return f"IP Analysis for {ip}:\n  Threat Score: {t.score}\n  Level: {t.level}\n  Action: {t.action}\n  Signals: {', '.join(t.signals) or 'none'}\n  Confidence: {t.confidence}"
        elif intent == "vuln_scan":
            result = vuln_full_scan()
            s = result.get("security_score", "?")
            c = result.get("critical", 0)
            w = result.get("warnings", 0)
            p = result.get("passed", 0)
            out = f"Vulnerability Scan Complete\n  Security Score: {s}/10\n  Critical: {c}  Warnings: {w}  Passed: {p}\n"
            for f in result.get("critical_findings", []):
                out += f"\n  [CRITICAL] {f['check']} (severity {f['severity']})"
            for f in result.get("warning_findings", []):
                out += f"\n  [WARNING] {f['check']} (severity {f['severity']})"
            return out
        elif intent == "ioc_scan":
            result = ioc_full_scan()
            return f"IOC Scan Complete\n  Compromise Likelihood: {result.get('compromise_likelihood', '?')}\n  Total Findings: {result.get('total_findings', 0)}\n  Critical: {result.get('critical', 0)}  Warnings: {result.get('warnings', 0)}  Clean: {result.get('clean', 0)}"
        elif intent == "forensics":
            result = full_forensic_capture()
            return f"Forensic Capture Complete\n  Risk Level: {result.get('risk_level', '?')}\n  Report saved to: {result.get('report_saved_to', 'N/A')}"
        elif intent == "password_audit":
            result = password_full_audit()
            return f"Password Audit Complete\n  Credential Security Score: {result.get('credential_security_score', '?')}/10\n  Critical: {result.get('critical', 0)}  Warnings: {result.get('warnings', 0)}  Passed: {result.get('passed', 0)}"
        elif intent == "payload_scan":
            result = payload_scan_web()
            return f"Payload Scan Complete\n  Files Scanned: {result.get('files_scanned', 0)}\n  Attack Detections: {result.get('total_detections', 0)}"
        elif intent == "honeypot_stats":
            result = analyze_honeypot_logs()
            if result.get("status") == "no_honeypot_data":
                return "No honeypot data yet. Start the honeypot first."
            return f"Honeypot Stats\n  Total Connections: {result.get('total_connections', 0)}\n  Unique IPs: {result.get('unique_ips', 0)}"
        elif intent == "uptime":
            result = uptime_checks()
            out = f"Uptime: {result.get('up', 0)}/{result.get('checks', 0)} services up\n"
            for r in result.get("results", []):
                name = r.get("url") or r.get("hostname") or f"{r.get('host')}:{r.get('port')}"
                status = r.get("status", "?")
                ms = r.get("response_ms", "?")
                icon = "UP" if status in ("up", "open", "resolved", "valid") else "DOWN"
                out += f"  [{icon}] {name} - {ms}ms\n"
            return out
        elif intent == "log_analysis":
            result = analyze_system_logs()
            return f"Log Analysis\n  Files: {result.get('files_analyzed', 0)}\n  Findings: {result.get('total_findings', 0)}\n  Categories: {json.dumps(result.get('categories', {}))}"
        elif intent == "threat_analysis":
            result = analyze_aegis_threats()
            return f"Threat History\n  Events: {result.get('total_events', 0)}\n  Actions: {json.dumps(result.get('action_distribution', {}))}"
        elif intent == "hashes":
            result = hash_critical_binaries()
            out = f"Binary Integrity ({result.get('binaries_hashed', 0)} files)\n"
            for b, info in result.get("hashes", {}).items():
                if isinstance(info, dict) and "sha256" in info:
                    out += f"  {b}: {info['sha256'][:16]}...\n"
            return out
        elif intent == "whois":
            return _run(f"whois {args[0]} 2>/dev/null | head -40") if args else "Usage: whois <domain or IP>"
        elif intent == "dns_lookup":
            return _run(f"dig {args[0]} +short 2>/dev/null || nslookup {args[0]} 2>/dev/null") if args else "Usage: lookup <domain>"
        elif intent == "ping":
            return _run(f"ping -c 4 {args[0]} 2>/dev/null") if args else "Usage: ping <host>"
        elif intent == "port_scan":
            target = args[0] if args else ""
            if _run("which nmap 2>/dev/null"):
                return _run(f"nmap -T4 -F {target} 2>/dev/null", timeout=60)
            return _run(f"timeout 10 bash -c 'for p in 21 22 23 25 53 80 443 3306 5432 6379 8080 8443 9200; do (echo >/dev/tcp/{target}/$p) 2>/dev/null && echo \"Port $p: OPEN\"; done'")
        elif intent == "traceroute":
            return _run(f"traceroute -m 15 {args[0]} 2>/dev/null || tracepath {args[0]} 2>/dev/null") if args else "Usage: traceroute <host>"
        elif intent == "listening_ports":
            return _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        elif intent == "connections":
            return _run("ss -tunapo 2>/dev/null | head -40")
        elif intent == "processes":
            return _run("ps aux --sort=-%cpu 2>/dev/null | head -25")
        elif intent == "firewall":
            return _run("sudo -n ufw status verbose 2>/dev/null || echo 'UFW not accessible'")
        elif intent == "disk":
            return _run("df -h 2>/dev/null")
        elif intent == "memory":
            return _run("free -h 2>/dev/null")
        elif intent == "cpu":
            return _run("top -bn1 | head -5 2>/dev/null; lscpu | grep -E 'Model name|CPU' 2>/dev/null")
        elif intent == "system_info":
            return _run("uname -a") + "\n" + _run("uptime") + "\n" + _run("free -h | head -2") + "\n" + _run("df -h / | tail -1")
        elif intent == "users":
            return _run("who 2>/dev/null") + "\n\nRecent:\n" + _run("last -n 10 2>/dev/null")
        elif intent == "my_ip":
            local = _run("hostname -I 2>/dev/null")
            public = _run("curl -s --max-time 5 ifconfig.me 2>/dev/null || echo 'unavailable'")
            return f"Local: {local}\nPublic: {public}"
        elif intent == "routes":
            return _run("ip route 2>/dev/null")
        elif intent == "arp":
            return _run("ip neigh 2>/dev/null")
        elif intent == "kernel":
            return _run("uname -a") + "\n" + _run("cat /etc/os-release 2>/dev/null | head -5")
        elif intent == "cron":
            return _run("crontab -l 2>/dev/null || echo 'No crontab'") + "\n\n" + _run("ls /etc/cron.d/ 2>/dev/null")
        elif intent == "services":
            return _run("systemctl list-units --type=service --state=running 2>/dev/null | head -30")
        elif intent == "wifi":
            return _run("iwconfig 2>/dev/null || echo 'No wireless'") + "\n" + _run("nmcli dev wifi list 2>/dev/null | head -15 || true")
        elif intent == "block_ip":
            ip = args[0] if args else ""
            bf = BASE / "data" / "blocklist.txt"
            bf.parent.mkdir(parents=True, exist_ok=True)
            with open(bf, "a") as f:
                f.write(ip + "\n")
            return f"IP {ip} added to AEGIS blocklist."
        elif intent == "blocklist":
            bf = BASE / "data" / "blocklist.txt"
            if bf.exists():
                ips = sorted(set(bf.read_text().strip().splitlines()))
                return f"Blocked IPs ({len(ips)}):\n" + "\n".join(f"  {ip}" for ip in ips)
            return "Blocklist is empty."
        elif intent == "full_audit":
            parts = ["=== FULL SECURITY AUDIT ==="]
            v = vuln_full_scan()
            parts.append(f"\nVulnerability Score: {v.get('security_score', '?')}/10  Critical: {v.get('critical', 0)}")
            i = ioc_full_scan()
            parts.append(f"IOC Likelihood: {i.get('compromise_likelihood', '?')}  Findings: {i.get('total_findings', 0)}")
            p = password_full_audit()
            parts.append(f"Credential Score: {p.get('credential_security_score', '?')}/10")
            u = uptime_checks()
            parts.append(f"Uptime: {u.get('up', 0)}/{u.get('checks', 0)} services up")
            return "\n".join(parts)
        elif intent == "set_key":
            return "To configure API keys, type:\n  set key anthropic sk-ant-...\n  set key openai sk-..."
        elif intent == "show_config":
            return "Type 'config' to see current settings."
        elif intent == "greeting":
            import random
            greetings = [
                "Hey! AEGIS AI here. What can I do for you?",
                "Hello! Ready to scan, analyze, or secure your system. What do you need?",
                "Hey there! Your security assistant is standing by. Ask me anything.",
                "Greetings! All systems operational. What would you like me to check?",
            ]
            return random.choice(greetings)
        elif intent == "help":
            return """AEGIS AI v3.0 — Advanced Security Assistant

SECURITY SCANS:
  "scan for vulnerabilities"     "check for malware"
  "run forensics"                "audit passwords"
  "scan for web attacks"         "show honeypot stats"
  "hash system binaries"         "run full audit"

NETWORK TOOLS:
  "scan IP 1.2.3.4"              "port scan 192.168.1.1"
  "what ports are open?"          "show connections"
  "ping google.com"               "traceroute 8.8.8.8"
  "lookup DNS github.com"         "whois cloudflare.com"
  "block IP 1.2.3.4"              "show blocked IPs"

SYSTEM MONITOR:
  "check disk/memory/cpu"         "show processes"
  "firewall status"               "check wifi"
  "show services"                 "who is logged in"
  "what's my IP?"                 "show cron jobs"

AI CONFIG:
  "set key anthropic sk-ant-..."  (enable Claude AI)
  "set key openai sk-..."         (enable GPT AI)

Or just ask me anything naturally!"""
        else:
            return None
    except Exception as e:
        return f"Error: {e}"


# ─── GPU-accelerated canvas gauges ──────────────────────────────────────────

class GaugeWidget(tk.Canvas):
    def __init__(self, parent, label="", value=0, max_val=100, theme=None, **kw):
        self.theme = theme or THEMES["hacker"]
        super().__init__(parent, width=140, height=80, bg=self.theme["bg"],
                         highlightthickness=0, **kw)
        self.label = label
        self.value = value
        self.max_val = max_val
        self._draw()

    def set_value(self, value):
        self.value = min(value, self.max_val)
        self._draw()

    def _draw(self):
        self.delete("all")
        t = self.theme
        w, h = 140, 80
        pct = self.value / self.max_val if self.max_val else 0

        if pct < 0.5:
            color = t["gauge_low"]
        elif pct < 0.8:
            color = t["gauge_mid"]
        else:
            color = t["gauge_high"]

        # arc background
        self.create_arc(15, 10, w - 15, h + 40, start=0, extent=180,
                        outline=t["accent_dim"], width=8, style="arc")
        # arc fill
        extent = 180 * pct
        self.create_arc(15, 10, w - 15, h + 40, start=180, extent=-extent,
                        outline=color, width=8, style="arc")
        # value
        self.create_text(w // 2, 48, text=f"{self.value:.0f}%",
                         fill=color, font=("Consolas", 14, "bold"))
        # label
        self.create_text(w // 2, 70, text=self.label,
                         fill=t["text_dim"], font=("Consolas", 8))


class StatusBar(tk.Canvas):
    def __init__(self, parent, theme, **kw):
        self.theme = theme
        super().__init__(parent, height=26, bg=theme["header"],
                         highlightthickness=0, **kw)
        self.items = {}
        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, e=None):
        self._redraw()

    def update_stats(self, stats):
        self.items = stats
        self._redraw()

    def _redraw(self):
        self.delete("all")
        t = self.theme
        w = self.winfo_width()
        # separator line
        self.create_line(0, 0, w, 0, fill=t["border"])

        x = 12
        for key, val in self.items.items():
            label_text = f"{key}: {val}"
            self.create_text(x, 13, text=label_text, anchor="w",
                             fill=t["text_dim"], font=("Consolas", 8))
            x += len(label_text) * 7 + 20


# ─── Settings Dialog ────────────────────────────────────────────────────────

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent, config, on_save):
        super().__init__(parent)
        self.config = dict(config)
        self.on_save = on_save
        self.title("AEGIS Settings")
        self.geometry("520x620")
        self.configure(bg="#111111")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self._build()

    def _build(self):
        bg = "#111111"
        fg = "#cccccc"
        accent = "#00ff88"
        entry_bg = "#1a1a1a"

        main = tk.Frame(self, bg=bg, padx=20, pady=15)
        main.pack(fill=tk.BOTH, expand=True)

        tk.Label(main, text="AEGIS Settings", font=("Consolas", 16, "bold"),
                 fg=accent, bg=bg).pack(anchor="w", pady=(0, 15))

        # ── Appearance ──
        self._section(main, "APPEARANCE")

        row = tk.Frame(main, bg=bg)
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text="Theme", fg=fg, bg=bg, font=("Consolas", 10), width=18, anchor="w").pack(side=tk.LEFT)
        self.theme_var = tk.StringVar(value=self.config["theme"])
        theme_menu = ttk.Combobox(row, textvariable=self.theme_var,
                                  values=list(THEMES.keys()), state="readonly", width=20)
        theme_menu.pack(side=tk.LEFT)

        row = tk.Frame(main, bg=bg)
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text="Font Size", fg=fg, bg=bg, font=("Consolas", 10), width=18, anchor="w").pack(side=tk.LEFT)
        self.fontsize_var = tk.IntVar(value=self.config["font_size"])
        tk.Spinbox(row, from_=8, to=20, textvariable=self.fontsize_var, width=5,
                   bg=entry_bg, fg=fg, buttonbackground="#222", font=("Consolas", 10)).pack(side=tk.LEFT)

        row = tk.Frame(main, bg=bg)
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text="Font Family", fg=fg, bg=bg, font=("Consolas", 10), width=18, anchor="w").pack(side=tk.LEFT)
        self.fontfam_var = tk.StringVar(value=self.config["font_family"])
        ttk.Combobox(row, textvariable=self.fontfam_var,
                     values=["Consolas", "Courier New", "Monospace", "DejaVu Sans Mono",
                             "Ubuntu Mono", "Fira Code", "Source Code Pro"],
                     state="readonly", width=20).pack(side=tk.LEFT)

        row = tk.Frame(main, bg=bg)
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text="Window Opacity", fg=fg, bg=bg, font=("Consolas", 10), width=18, anchor="w").pack(side=tk.LEFT)
        self.opacity_var = tk.DoubleVar(value=self.config["opacity"])
        tk.Scale(row, from_=0.5, to=1.0, resolution=0.05, orient=tk.HORIZONTAL,
                 variable=self.opacity_var, bg=bg, fg=fg, troughcolor=entry_bg,
                 highlightthickness=0, length=160, font=("Consolas", 8)).pack(side=tk.LEFT)

        # ── Behavior ──
        self._section(main, "BEHAVIOR")

        self.autoscroll_var = tk.BooleanVar(value=self.config["auto_scroll"])
        tk.Checkbutton(main, text="Auto-scroll chat", variable=self.autoscroll_var,
                       fg=fg, bg=bg, selectcolor=entry_bg, activebackground=bg,
                       activeforeground=fg, font=("Consolas", 10)).pack(anchor="w", pady=1)

        self.timestamps_var = tk.BooleanVar(value=self.config["timestamp_messages"])
        tk.Checkbutton(main, text="Show timestamps on messages", variable=self.timestamps_var,
                       fg=fg, bg=bg, selectcolor=entry_bg, activebackground=bg,
                       activeforeground=fg, font=("Consolas", 10)).pack(anchor="w", pady=1)

        self.animations_var = tk.BooleanVar(value=self.config["enable_animations"])
        tk.Checkbutton(main, text="Enable animations", variable=self.animations_var,
                       fg=fg, bg=bg, selectcolor=entry_bg, activebackground=bg,
                       activeforeground=fg, font=("Consolas", 10)).pack(anchor="w", pady=1)

        self.confirm_var = tk.BooleanVar(value=self.config["confirm_destructive"])
        tk.Checkbutton(main, text="Confirm destructive actions", variable=self.confirm_var,
                       fg=fg, bg=bg, selectcolor=entry_bg, activebackground=bg,
                       activeforeground=fg, font=("Consolas", 10)).pack(anchor="w", pady=1)

        self.logconv_var = tk.BooleanVar(value=self.config["log_conversations"])
        tk.Checkbutton(main, text="Log conversations to disk", variable=self.logconv_var,
                       fg=fg, bg=bg, selectcolor=entry_bg, activebackground=bg,
                       activeforeground=fg, font=("Consolas", 10)).pack(anchor="w", pady=1)

        self.stats_var = tk.BooleanVar(value=self.config["show_system_stats"])
        tk.Checkbutton(main, text="Show live system stats panel", variable=self.stats_var,
                       fg=fg, bg=bg, selectcolor=entry_bg, activebackground=bg,
                       activeforeground=fg, font=("Consolas", 10)).pack(anchor="w", pady=1)

        # ── Privileges ──
        self._section(main, "PRIVILEGE LEVEL")

        row = tk.Frame(main, bg=bg)
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text="Access Level", fg=fg, bg=bg, font=("Consolas", 10), width=18, anchor="w").pack(side=tk.LEFT)
        self.priv_var = tk.StringVar(value=self.config["privilege_level"])
        priv_menu = ttk.Combobox(row, textvariable=self.priv_var,
                                 values=list(PRIVILEGE_LEVELS.keys()), state="readonly", width=20)
        priv_menu.pack(side=tk.LEFT)

        for lvl, info in PRIVILEGE_LEVELS.items():
            allowed = "all commands" if info["allowed"] == "all" else f"{len(info['allowed'])} commands"
            tk.Label(main, text=f"  {lvl}: {info['label']} ({allowed})",
                     fg="#555555", bg=bg, font=("Consolas", 9)).pack(anchor="w")

        # ── API ──
        self._section(main, "AI PROVIDER")

        row = tk.Frame(main, bg=bg)
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text="Provider", fg=fg, bg=bg, font=("Consolas", 10), width=18, anchor="w").pack(side=tk.LEFT)
        self.provider_var = tk.StringVar(value=self.config["api_provider"])
        ttk.Combobox(row, textvariable=self.provider_var,
                     values=["auto", "claude", "openai", "local"],
                     state="readonly", width=20).pack(side=tk.LEFT)

        # ── Buttons ──
        btn_frame = tk.Frame(main, bg=bg)
        btn_frame.pack(fill=tk.X, pady=(20, 0))

        tk.Button(btn_frame, text="Save", command=self._save,
                  bg=accent, fg="#000", font=("Consolas", 11, "bold"),
                  relief=tk.FLAT, padx=25, pady=4, cursor="hand2").pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=self.destroy,
                  bg="#333", fg="#aaa", font=("Consolas", 11),
                  relief=tk.FLAT, padx=25, pady=4, cursor="hand2").pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="Reset Defaults", command=self._reset,
                  bg="#331111", fg="#ff6644", font=("Consolas", 10),
                  relief=tk.FLAT, padx=15, pady=4, cursor="hand2").pack(side=tk.LEFT)

    def _section(self, parent, title):
        f = tk.Frame(parent, bg="#111111")
        f.pack(fill=tk.X, pady=(12, 4))
        tk.Label(f, text=f"── {title} ", fg="#444444", bg="#111111",
                 font=("Consolas", 9, "bold")).pack(anchor="w")

    def _save(self):
        self.config["theme"] = self.theme_var.get()
        self.config["font_size"] = self.fontsize_var.get()
        self.config["font_family"] = self.fontfam_var.get()
        self.config["opacity"] = self.opacity_var.get()
        self.config["auto_scroll"] = self.autoscroll_var.get()
        self.config["timestamp_messages"] = self.timestamps_var.get()
        self.config["enable_animations"] = self.animations_var.get()
        self.config["confirm_destructive"] = self.confirm_var.get()
        self.config["log_conversations"] = self.logconv_var.get()
        self.config["show_system_stats"] = self.stats_var.get()
        self.config["privilege_level"] = self.priv_var.get()
        self.config["api_provider"] = self.provider_var.get()
        self.on_save(self.config)
        self.destroy()

    def _reset(self):
        self.on_save(dict(DEFAULT_CONFIG))
        self.destroy()


# ─── Advanced Tools Panel ───────────────────────────────────────────────────

class ToolsPanel(tk.Toplevel):
    def __init__(self, parent, theme, on_run):
        super().__init__(parent)
        self.theme = theme
        self.on_run = on_run
        t = theme
        self.title("AEGIS Advanced Tools")
        self.geometry("440x560")
        self.configure(bg=t["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self._build()

    def _build(self):
        t = self.theme
        main = tk.Frame(self, bg=t["bg"], padx=15, pady=10)
        main.pack(fill=tk.BOTH, expand=True)

        tk.Label(main, text="Advanced Security Tools", font=("Consolas", 14, "bold"),
                 fg=t["accent"], bg=t["bg"]).pack(anchor="w", pady=(0, 10))

        categories = {
            "THREAT DETECTION": [
                ("IOC Deep Scan", "ioc_scan", "Indicators of compromise — processes, persistence, SSH, hidden files"),
                ("Vulnerability Scan", "vuln_scan", "System hardening and CVE checks"),
                ("Payload Detection", "payload_scan", "SQLi, XSS, command injection in logs"),
                ("Forensic Capture", "forensics", "Volatile state, kernel modules, file handles"),
            ],
            "CREDENTIAL SECURITY": [
                ("Password Policy Audit", "password_audit", "PAM config, shadow file, aging policies"),
                ("Binary Integrity", "hashes", "SHA-256 hash verification of critical binaries"),
            ],
            "MONITORING": [
                ("Service Uptime", "uptime", "HTTP, TCP, DNS, SSL endpoint checks"),
                ("Log Analysis", "log_analysis", "Auth failures, kernel errors, SSH events"),
                ("Honeypot Analytics", "honeypot_stats", "Decoy service connection data"),
                ("Threat History", "threat_analysis", "Historical threat event patterns"),
            ],
            "FULL OPERATIONS": [
                ("Full Security Audit", "full_audit", "All scans combined — comprehensive report"),
            ],
        }

        for cat_name, tools in categories.items():
            tk.Label(main, text=f"── {cat_name} ", fg=t["text_dim"], bg=t["bg"],
                     font=("Consolas", 9, "bold")).pack(anchor="w", pady=(10, 3))

            for tool_name, intent, desc in tools:
                row = tk.Frame(main, bg=t["card_bg"], padx=8, pady=6,
                               highlightbackground=t["border"], highlightthickness=1)
                row.pack(fill=tk.X, pady=2)

                left = tk.Frame(row, bg=t["card_bg"])
                left.pack(side=tk.LEFT, fill=tk.X, expand=True)

                tk.Label(left, text=tool_name, fg=t["text_bright"], bg=t["card_bg"],
                         font=("Consolas", 10, "bold"), anchor="w").pack(anchor="w")
                tk.Label(left, text=desc, fg=t["text_dim"], bg=t["card_bg"],
                         font=("Consolas", 8), anchor="w", wraplength=280).pack(anchor="w")

                tk.Button(row, text="Run", command=lambda i=intent: self._execute(i),
                          bg=t["accent"], fg=t["btn_fg"], font=("Consolas", 9, "bold"),
                          relief=tk.FLAT, padx=12, pady=2, cursor="hand2",
                          activebackground=t["accent2"]).pack(side=tk.RIGHT, pady=2)

    def _execute(self, intent):
        self.on_run(intent)


# ─── Main GUI ───────────────────────────────────────────────────────────────

class AegisChatGUI:
    def __init__(self):
        self.config = _load_config()
        self.theme = THEMES.get(self.config["theme"], THEMES["hacker"])

        self.root = tk.Tk()
        self.root.title("AEGIS AI v3.0 — Advanced Security Assistant")
        self.root.geometry(f"{self.config['window_width']}x{self.config['window_height']}")
        self.root.configure(bg=self.theme["bg"])
        self.root.minsize(800, 600)

        try:
            self.root.attributes('-alpha', self.config["opacity"])
        except Exception:
            pass

        self.brain = None
        try:
            from aegis_brain import AegisBrain
            self.brain = AegisBrain()
        except Exception:
            pass

        self.msg_count = 0
        self._build_ui()
        self._show_welcome()

        if self.config["show_system_stats"] and HAS_PSUTIL:
            self._start_stats_monitor()

    def _apply_theme(self):
        self.theme = THEMES.get(self.config["theme"], THEMES["hacker"])
        t = self.theme
        self.root.configure(bg=t["bg"])
        try:
            self.root.attributes('-alpha', self.config["opacity"])
        except Exception:
            pass

    def _build_ui(self):
        t = self.theme
        ff = self.config["font_family"]
        fs = self.config["font_size"]

        # ── Header ──
        self.header = tk.Frame(self.root, bg=t["header"], height=50)
        self.header.pack(fill=tk.X)
        self.header.pack_propagate(False)

        # logo area
        logo_frame = tk.Frame(self.header, bg=t["header"])
        logo_frame.pack(side=tk.LEFT, padx=12)

        logo_canvas = tk.Canvas(logo_frame, width=32, height=32, bg=t["header"],
                                highlightthickness=0)
        logo_canvas.pack(side=tk.LEFT, pady=9)
        logo_canvas.create_polygon(16, 2, 30, 12, 26, 28, 6, 28, 2, 12,
                                   fill=t["accent_dim"], outline=t["accent"], width=2)
        logo_canvas.create_text(16, 17, text="A", fill=t["accent"],
                                font=(ff, 11, "bold"))

        tk.Label(logo_frame, text=" AEGIS AI", font=(ff, 15, "bold"),
                 fg=t["accent"], bg=t["header"]).pack(side=tk.LEFT)

        sub_text = "QByte-22 Engine"
        if self.brain:
            providers = self.brain.get_provider_status()
            if providers.get("claude") == "ready":
                sub_text += "  |  Claude"
            if providers.get("openai") == "ready":
                sub_text += "  |  GPT"
        tk.Label(logo_frame, text=f"  {sub_text}", font=(ff, 8),
                 fg=t["text_dim"], bg=t["header"]).pack(side=tk.LEFT, padx=8)

        # header buttons
        btn_frame = tk.Frame(self.header, bg=t["header"])
        btn_frame.pack(side=tk.RIGHT, padx=8)

        for btn_text, btn_cmd in [
            ("Tools", self._open_tools),
            ("Settings", self._open_settings),
            ("Export", self._export_chat),
            ("Clear", self._clear_chat),
        ]:
            b = tk.Button(btn_frame, text=btn_text, command=btn_cmd,
                          bg=t["accent_dim"], fg=t["accent"], font=(ff, 9),
                          relief=tk.FLAT, padx=10, pady=2, cursor="hand2",
                          activebackground=t["border"], activeforeground=t["text_bright"])
            b.pack(side=tk.LEFT, padx=3, pady=10)

        priv = PRIVILEGE_LEVELS.get(self.config["privilege_level"], {})
        priv_label = priv.get("label", "User")
        self.priv_indicator = tk.Label(btn_frame, text=f"[{priv_label}]",
                                       font=(ff, 8), fg=t["warn"], bg=t["header"])
        self.priv_indicator.pack(side=tk.LEFT, padx=(10, 0))

        # ── Status bar (pack FIRST from bottom) ──
        self.statusbar = StatusBar(self.root, t)
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)

        # ── Input bar (pack SECOND from bottom — always visible) ──
        input_outer = tk.Frame(self.root, bg=t["header"], padx=10, pady=8)
        input_outer.pack(side=tk.BOTTOM, fill=tk.X)

        input_inner = tk.Frame(input_outer, bg=t["input_bg"],
                               highlightbackground=t["border"], highlightthickness=1)
        input_inner.pack(fill=tk.X)

        input_font = tkfont.Font(family=ff, size=fs + 1)
        self.entry = tk.Entry(
            input_inner, bg=t["input_bg"], fg=t["text_bright"],
            insertbackground=t["accent"], font=input_font,
            relief=tk.FLAT, borderwidth=10,
        )
        self.entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.entry.bind("<Return>", self._on_send)
        self.entry.bind("<Up>", self._history_prev)
        self.entry.bind("<Down>", self._history_next)
        self.entry.focus_set()

        send_btn = tk.Button(
            input_inner, text="  SEND  ", command=self._on_send,
            bg=t["accent"], fg=t["btn_fg"], font=(ff, 11, "bold"),
            relief=tk.FLAT, padx=18, pady=6,
            activebackground=t["accent2"], cursor="hand2",
        )
        send_btn.pack(side=tk.RIGHT, padx=6, pady=6)

        # ── Main body (fills remaining space) ──
        body = tk.Frame(self.root, bg=t["bg"])
        body.pack(fill=tk.BOTH, expand=True)

        # stats sidebar on the right
        if self.config["show_system_stats"] and HAS_PSUTIL:
            self.stats_frame = tk.Frame(body, bg=t["bg"], width=160)
            self.stats_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 4), pady=4)
            self.stats_frame.pack_propagate(False)

            tk.Label(self.stats_frame, text="SYSTEM", font=(ff, 9, "bold"),
                     fg=t["accent"], bg=t["bg"]).pack(pady=(10, 5))

            sep = tk.Frame(self.stats_frame, bg=t["border"], height=1)
            sep.pack(fill=tk.X, padx=10, pady=2)

            self.cpu_gauge = GaugeWidget(self.stats_frame, "CPU", theme=t)
            self.cpu_gauge.pack(pady=4, padx=5)

            self.mem_gauge = GaugeWidget(self.stats_frame, "RAM", theme=t)
            self.mem_gauge.pack(pady=4, padx=5)

            self.disk_gauge = GaugeWidget(self.stats_frame, "DISK", theme=t)
            self.disk_gauge.pack(pady=4, padx=5)

            sep2 = tk.Frame(self.stats_frame, bg=t["border"], height=1)
            sep2.pack(fill=tk.X, padx=10, pady=6)

            self.net_label = tk.Label(self.stats_frame, text="NET: ...",
                                      font=(ff, 8), fg=t["text_dim"], bg=t["bg"],
                                      anchor="w", justify=tk.LEFT)
            self.net_label.pack(padx=10, anchor="w")

            self.proc_label = tk.Label(self.stats_frame, text="PROCS: ...",
                                        font=(ff, 8), fg=t["text_dim"], bg=t["bg"],
                                        anchor="w")
            self.proc_label.pack(padx=10, anchor="w", pady=2)

            self.uptime_label = tk.Label(self.stats_frame, text="UP: ...",
                                          font=(ff, 8), fg=t["text_dim"], bg=t["bg"],
                                          anchor="w")
            self.uptime_label.pack(padx=10, anchor="w", pady=2)
        else:
            self.stats_frame = None

        # chat area fills the rest
        chat_font = tkfont.Font(family=ff, size=fs)
        self.chat = scrolledtext.ScrolledText(
            body, wrap=tk.WORD, bg=t["bg2"], fg=t["text"],
            insertbackground=t["accent"], font=chat_font,
            relief=tk.FLAT, borderwidth=0, state=tk.DISABLED,
            selectbackground=t["accent_dim"], selectforeground=t["accent"],
            padx=14, pady=12, spacing3=5,
        )
        self.chat.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 4), pady=(6, 4))

        bold_font = tkfont.Font(family=ff, size=fs, weight="bold")
        self.chat.tag_configure("user_label", foreground=t["user_color"], font=bold_font)
        self.chat.tag_configure("user_text", foreground=t["text_bright"])
        self.chat.tag_configure("aegis_label", foreground=t["accent"], font=bold_font)
        self.chat.tag_configure("aegis_text", foreground=t["text"])
        self.chat.tag_configure("system", foreground=t["error"],
                                font=tkfont.Font(family=ff, size=fs - 1))
        self.chat.tag_configure("dim", foreground=t["text_dim"],
                                font=tkfont.Font(family=ff, size=fs - 2))
        self.chat.tag_configure("thinking", foreground=t["text_dim"],
                                font=tkfont.Font(family=ff, size=fs - 1, slant="italic"))
        self.chat.tag_configure("timestamp", foreground=t["text_dim"],
                                font=tkfont.Font(family=ff, size=fs - 3))
        self.chat.tag_configure("separator", foreground=t["border"],
                                font=tkfont.Font(family=ff, size=4))

        self.cmd_history = []
        self.history_idx = -1

    def _show_welcome(self):
        t = self.theme
        self._append_aegis(f"""AEGIS AI v{__version__} — Advanced Security Assistant
QByte-22 Quantum Security Engine initialized.

{PRIVILEGE_LEVELS[self.config['privilege_level']]['label']} mode active.
Theme: {t['name']}

Type 'help' for commands, or talk naturally.
Open Tools panel for one-click security operations.""")

        if self.brain:
            providers = self.brain.get_provider_status()
            active = [k for k, v in providers.items() if v == "ready"]
            if active:
                self._append_system(f"AI engines: {', '.join(active)}")
            else:
                self._append_system("No API keys configured — using local intent engine.\nUse Settings or type: set key anthropic YOUR_KEY")
        else:
            self._append_system("Local engine active. Configure API keys in Settings for AI chat.")

        self.statusbar.update_stats({
            "Mode": self.config["privilege_level"].upper(),
            "Theme": t["name"],
            "Version": __version__,
        })

    def _check_privilege(self, intent):
        level = self.config["privilege_level"]
        priv = PRIVILEGE_LEVELS.get(level, PRIVILEGE_LEVELS["user"])
        if priv["allowed"] == "all":
            blocked = priv.get("except", [])
            if intent in blocked:
                return False, f"Action '{intent}' requires higher privilege (current: {priv['label']})"
            return True, ""
        if intent in priv["allowed"]:
            return True, ""
        return False, f"Action '{intent}' not allowed at {priv['label']} level. Switch to Operator or Admin in Settings."

    def _append_user(self, text):
        self.chat.config(state=tk.NORMAL)
        if self.config["timestamp_messages"]:
            ts = datetime.now().strftime("%H:%M:%S")
            self.chat.insert(tk.END, f"  {ts}\n", "timestamp")
        self.chat.insert(tk.END, "  You\n", "user_label")
        self.chat.insert(tk.END, f"  {text}\n\n", "user_text")
        self.chat.config(state=tk.DISABLED)
        if self.config["auto_scroll"]:
            self.chat.see(tk.END)

    def _append_aegis(self, text):
        self.chat.config(state=tk.NORMAL)
        if self.config["timestamp_messages"]:
            ts = datetime.now().strftime("%H:%M:%S")
            self.chat.insert(tk.END, f"  {ts}\n", "timestamp")
        self.chat.insert(tk.END, "  AEGIS\n", "aegis_label")
        for line in text.split("\n"):
            self.chat.insert(tk.END, f"  {line}\n", "aegis_text")
        self.chat.insert(tk.END, "\n", "aegis_text")
        self.chat.config(state=tk.DISABLED)
        if self.config["auto_scroll"]:
            self.chat.see(tk.END)

    def _append_system(self, text):
        self.chat.config(state=tk.NORMAL)
        self.chat.insert(tk.END, f"  {text}\n\n", "dim")
        self.chat.config(state=tk.DISABLED)

    def _append_thinking(self):
        self.chat.config(state=tk.NORMAL)
        self.chat.insert(tk.END, "  AEGIS\n", "aegis_label")
        self.chat.insert(tk.END, "  Processing...\n\n", "thinking")
        self.chat.config(state=tk.DISABLED)
        if self.config["auto_scroll"]:
            self.chat.see(tk.END)

    def _remove_thinking(self):
        self.chat.config(state=tk.NORMAL)
        content = self.chat.get("1.0", tk.END)
        idx = content.rfind("  Processing...\n")
        if idx >= 0:
            before = content[:idx]
            aegis_idx = before.rfind("  AEGIS\n")
            if aegis_idx >= 0:
                start_line = before[:aegis_idx].count("\n") + 1
                end_line = content[:idx].count("\n") + 3
                self.chat.delete(f"{start_line}.0", f"{end_line}.0")
        self.chat.config(state=tk.DISABLED)

    def _on_send(self, event=None):
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, tk.END)
        self.cmd_history.append(msg)
        self.history_idx = len(self.cmd_history)
        self.msg_count += 1
        self._append_user(msg)
        self._append_thinking()
        self.statusbar.update_stats({
            "Mode": self.config["privilege_level"].upper(),
            "Messages": str(self.msg_count),
            "Last": datetime.now().strftime("%H:%M:%S"),
        })
        threading.Thread(target=self._process, args=(msg,), daemon=True).start()

    def _history_prev(self, event=None):
        if self.cmd_history and self.history_idx > 0:
            self.history_idx -= 1
            self.entry.delete(0, tk.END)
            self.entry.insert(0, self.cmd_history[self.history_idx])

    def _history_next(self, event=None):
        if self.history_idx < len(self.cmd_history) - 1:
            self.history_idx += 1
            self.entry.delete(0, tk.END)
            self.entry.insert(0, self.cmd_history[self.history_idx])
        else:
            self.history_idx = len(self.cmd_history)
            self.entry.delete(0, tk.END)

    def _process(self, msg):
        try:
            intent, args = match_intent(msg)
            if intent != "unknown":
                allowed, reason = self._check_privilege(intent)
                if not allowed:
                    self.root.after(0, self._show_response, f"ACCESS DENIED: {reason}")
                    return

            if self.brain:
                response = self.brain.chat(msg)
            else:
                local_result = execute_intent(intent, args)
                if local_result:
                    response = local_result
                else:
                    response = "I understood your request but couldn't process it. Try 'help' for examples."

            if not response:
                response = "No response generated. Try 'help' for available commands."

            if self.config["log_conversations"]:
                self._log_message(msg, response)

            self.root.after(0, self._show_response, response)
        except Exception as e:
            self.root.after(0, self._show_response, f"Error processing request: {e}")

    def _show_response(self, response):
        self._remove_thinking()
        self._append_aegis(response)

    def _log_message(self, user_msg, aegis_response):
        try:
            log_file = LOGS / "chat_history.jsonl"
            with open(log_file, "a") as f:
                f.write(json.dumps({
                    "time": datetime.now(UTC).isoformat(),
                    "user": user_msg,
                    "aegis": aegis_response[:500],
                }, default=str) + "\n")
        except Exception:
            pass

    def _open_settings(self):
        SettingsDialog(self.root, self.config, self._on_settings_save)

    def _on_settings_save(self, new_config):
        self.config = new_config
        _save_config(self.config)
        self._append_system("Settings saved. Restart AEGIS to fully apply theme changes.")
        priv = PRIVILEGE_LEVELS.get(self.config["privilege_level"], {})
        self.priv_indicator.config(text=f"[{priv.get('label', 'User')}]")

    def _open_tools(self):
        ToolsPanel(self.root, self.theme, self._run_tool)

    def _run_tool(self, intent):
        allowed, reason = self._check_privilege(intent)
        if not allowed:
            self._append_aegis(f"ACCESS DENIED: {reason}")
            return
        self._append_user(f"[Tool: {intent}]")
        self._append_thinking()
        threading.Thread(target=self._execute_tool, args=(intent,), daemon=True).start()

    def _execute_tool(self, intent):
        result = execute_intent(intent, [])
        if result is None:
            result = "Tool completed with no output."
        if self.config["log_conversations"]:
            self._log_message(f"[tool:{intent}]", result)
        self.root.after(0, self._show_response, result)

    def _export_chat(self):
        try:
            content = self.chat.get("1.0", tk.END)
            export_path = LOGS / f"chat_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            export_path.write_text(content)
            self._append_system(f"Chat exported to {export_path}")
        except Exception as e:
            self._append_system(f"Export failed: {e}")

    def _clear_chat(self):
        self.chat.config(state=tk.NORMAL)
        self.chat.delete("1.0", tk.END)
        self.chat.config(state=tk.DISABLED)
        self._append_system("Chat cleared.")

    def _start_stats_monitor(self):
        def _update():
            while True:
                try:
                    cpu = psutil.cpu_percent(interval=2)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage("/")
                    net = psutil.net_io_counters()
                    procs = len(psutil.pids())
                    boot = datetime.fromtimestamp(psutil.boot_time())
                    uptime_delta = datetime.now() - boot
                    hours = int(uptime_delta.total_seconds() // 3600)
                    mins = int((uptime_delta.total_seconds() % 3600) // 60)

                    sent_mb = net.bytes_sent / (1024 * 1024)
                    recv_mb = net.bytes_recv / (1024 * 1024)

                    self.root.after(0, self.cpu_gauge.set_value, cpu)
                    self.root.after(0, self.mem_gauge.set_value, mem.percent)
                    self.root.after(0, self.disk_gauge.set_value, disk.percent)
                    self.root.after(0, self.net_label.config,
                                   {"text": f"TX: {sent_mb:.0f}MB\nRX: {recv_mb:.0f}MB"})
                    self.root.after(0, self.proc_label.config,
                                   {"text": f"PROCS: {procs}"})
                    self.root.after(0, self.uptime_label.config,
                                   {"text": f"UP: {hours}h {mins}m"})
                except Exception:
                    pass
                time.sleep(3)

        t = threading.Thread(target=_update, daemon=True)
        t.start()

    def run(self):
        self.root.mainloop()


# ─── CLI fallback ───────────────────────────────────────────────────────────

def cli_chat():
    brain = None
    try:
        from aegis_brain import AegisBrain
        brain = AegisBrain()
    except Exception:
        pass

    print(f"\nAEGIS AI Security Assistant v{__version__} — QByte-22 Engine")
    if brain:
        providers = brain.get_provider_status()
        active = [k for k, v in providers.items() if v == "ready"]
        print(f"AI engines: {', '.join(active) if active else 'local only'}")
    print("Talk naturally. 'help' for examples. 'exit' to quit.\n")

    while True:
        try:
            msg = input("You> ").strip()
            if msg.lower() in ("exit", "quit", "bye"):
                print("Goodbye.")
                break
            if not msg:
                continue
            if brain:
                response = brain.chat(msg)
            else:
                intent, args = match_intent(msg)
                response = execute_intent(intent, args) or "Unknown request. Try 'help'."
            print(f"\nAEGIS> {response}\n")
        except KeyboardInterrupt:
            print("\nGoodbye.")
            break


if __name__ == "__main__":
    if "--cli" in sys.argv or not HAS_TK:
        cli_chat()
    else:
        app = AegisChatGUI()
        app.run()
