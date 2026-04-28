#!/usr/bin/env python3
# Copyright (c) 2024-2026 Jorge Francisco Paredes (irstabyjorge)
# Licensed under dual MIT/Commercial license. See LICENSE and COMMERCIAL_LICENSE.md

__version__ = "1.0.0"

import os, json, subprocess, hashlib, time
from pathlib import Path
from datetime import datetime, UTC
from collections import Counter
import psutil
from rich.console import Console
from rich.table import Table
from cryptography.fernet import Fernet

console = Console()
BASE = Path.home() / "aegis_omni_xeon"
LOGS = BASE / "logs"
LOGS.mkdir(parents=True, exist_ok=True)
LOGFILE = LOGS / "aegis_unified_events.jsonl"

SUSPICIOUS_PORTS = {22, 23, 25, 3389, 4444, 5555, 6667, 8333, 9735, 18080, 18081}

def now():
    return datetime.now(UTC).isoformat()

def log(event, payload):
    with open(LOGFILE, "a") as f:
        f.write(json.dumps({"time": now(), "event": event, "payload": payload}, default=str) + "\n")

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=8)
        return {"ok": r.returncode == 0, "stdout": r.stdout[-4000:], "stderr": r.stderr[-2000:]}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def status():
    data = {
        "hostname": os.uname().nodename,
        "user": os.getenv("USER"),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage("/").percent,
        "logical_cpus": psutil.cpu_count(logical=True),
        "physical_cpus": psutil.cpu_count(logical=False),
        "boot_time": datetime.fromtimestamp(psutil.boot_time(), UTC).isoformat(),
    }
    log("status", data)
    return data

def listeners():
    rows = []
    for c in psutil.net_connections(kind="inet"):
        if c.status == "LISTEN":
            rows.append({
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "port": c.laddr.port if c.laddr else None,
                "pid": c.pid,
                "process": psutil.Process(c.pid).name() if c.pid else None,
                "status": c.status,
            })
    log("listeners", rows)
    return rows

def connections():
    rows = []
    for c in psutil.net_connections(kind="inet"):
        if c.raddr:
            rows.append({
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "remote": f"{c.raddr.ip}:{c.raddr.port}",
                "remote_ip": c.raddr.ip,
                "remote_port": c.raddr.port,
                "pid": c.pid,
                "process": psutil.Process(c.pid).name() if c.pid else None,
                "status": c.status,
            })
    log("connections", rows[:300])
    return rows[:300]

def threat_scan():
    conns = connections()
    lst = listeners()
    findings = []

    for x in conns:
        port = x.get("remote_port")
        if port in SUSPICIOUS_PORTS:
            findings.append({
                "type": "remote_suspicious_port",
                "severity": 7,
                "item": x,
                "recommendation": "review_process_and_remote_endpoint"
            })

    for x in lst:
        port = x.get("port")
        if port in SUSPICIOUS_PORTS:
            findings.append({
                "type": "local_sensitive_listener",
                "severity": 8 if port in {23,3389,4444,5555} else 5,
                "item": x,
                "recommendation": "verify_service_is_expected"
            })

    ips = [x["remote_ip"] for x in conns if x.get("remote_ip")]
    for ip, count in Counter(ips).most_common():
        if count >= 10:
            findings.append({
                "type": "high_connection_count_remote_ip",
                "severity": 6,
                "remote_ip": ip,
                "count": count,
                "recommendation": "investigate_repeated_connections"
            })

    log("threat_scan", findings)
    return findings

def auth():
    files = ["/var/log/auth.log", "/var/log/syslog"]
    findings = []
    for fp in files:
        if Path(fp).exists():
            r = run_cmd(f"sudo tail -n 300 {fp} | grep -Ei 'failed|invalid|authentication|sudo|session|password' || true")
            findings.append({"file": fp, "events": r.get("stdout", "")})
    log("auth", findings)
    return findings

def firewall():
    data = {
        "ufw": run_cmd("sudo ufw status verbose"),
        "iptables": run_cmd("sudo iptables -S | head -n 120"),
    }
    log("firewall", data)
    return data

def packages():
    data = {
        "python": run_cmd("python --version"),
        "pip": run_cmd("pip list"),
        "apt_preview": run_cmd("apt list --installed 2>/dev/null | head -n 120"),
        "snap": run_cmd("snap list 2>/dev/null || true"),
        "flatpak": run_cmd("flatpak list 2>/dev/null || true"),
    }
    log("packages", {"captured": True})
    return data

def entropy():
    key = Fernet.generate_key()
    digest = hashlib.sha512(key).hexdigest()
    data = {"fernet_key_created": True, "sha512_digest": digest, "stored": False}
    log("entropy", {"sha512_digest": digest})
    return data

def full_audit():
    data = {
        "status": status(),
        "listeners": listeners(),
        "connections": connections(),
        "threat_scan": threat_scan(),
        "auth": auth(),
        "firewall": firewall(),
        "packages": packages(),
        "entropy": entropy(),
        "logfile": str(LOGFILE),
    }
    log("full_audit", {"complete": True})
    return data

def table(title, rows):
    t = Table(title=title)
    if not rows:
        console.print("[yellow]No results.[/yellow]")
        return
    keys = list(rows[0].keys())
    for k in keys:
        t.add_column(str(k))
    for r in rows[:50]:
        t.add_row(*[str(r.get(k, "")) for k in keys])
    console.print(t)

def help_menu():
    return {
        "commands": [
            "status",
            "listeners",
            "connections",
            "threats",
            "auth",
            "firewall",
            "packages",
            "entropy",
            "all",
            "watch",
            "logs",
            "exit"
        ],
        "note": "No automatic blocking or destructive changes are performed."
    }

def main():
    console.print("[bold cyan]AEGIS UNIFIED AUTONOMOUS SYSTEM[/bold cyan]")
    console.print("Type help. Type all to run everything. Type watch for continuous monitoring.")

    while True:
        try:
            cmd = input("AEGIS-UNIFIED> ").strip().lower()

            if cmd in {"exit", "quit"}:
                break
            elif cmd == "help":
                console.print_json(json.dumps(help_menu()))
            elif cmd == "status":
                console.print_json(json.dumps(status(), default=str))
            elif cmd == "listeners":
                table("Listening Services", listeners())
            elif cmd == "connections":
                table("Active Connections", connections())
            elif cmd in {"threats", "scan"}:
                console.print_json(json.dumps(threat_scan(), default=str))
            elif cmd == "auth":
                console.print_json(json.dumps(auth(), default=str))
            elif cmd == "firewall":
                console.print_json(json.dumps(firewall(), default=str))
            elif cmd == "packages":
                console.print_json(json.dumps(packages(), default=str))
            elif cmd == "entropy":
                console.print_json(json.dumps(entropy(), default=str))
            elif cmd == "logs":
                console.print(run_cmd(f"tail -n 80 {LOGFILE}")["stdout"])
            elif cmd == "all":
                console.print_json(json.dumps(full_audit(), default=str))
            elif cmd == "watch":
                console.print("[green]Monitoring every 10 seconds. Ctrl+C to stop.[/green]")
                while True:
                    findings = threat_scan()
                    console.print_json(json.dumps({
                        "time": now(),
                        "cpu": psutil.cpu_percent(interval=1),
                        "memory": psutil.virtual_memory().percent,
                        "threat_findings": findings
                    }, default=str))
                    time.sleep(10)
            else:
                console.print({"unknown": cmd, "hint": "type help"})
        except KeyboardInterrupt:
            console.print("\nExiting.")
            break

if __name__ == "__main__":
    main()
