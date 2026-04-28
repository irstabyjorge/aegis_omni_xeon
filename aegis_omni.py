#!/usr/bin/env python3
# Copyright (c) 2024-2026 Jorge Francisco Paredes (irstabyjorge)
# Licensed under dual MIT/Commercial license. See LICENSE and COMMERCIAL_LICENSE.md

__version__ = "1.0.0"

import os, time, json, hashlib, random, queue, threading
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Dict, Any, List
import psutil
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from rich.console import Console
from rich.table import Table
from cryptography.fernet import Fernet

console = Console()
BASE = os.path.expanduser("~/aegis_omni_xeon")
LOG_DIR = os.path.join(BASE, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

def log(event: str, payload: Dict[str, Any] = None):
    entry = {
        "time": datetime.now(UTC).isoformat(),
        "event": event,
        "payload": payload or {}
    }
    with open(os.path.join(LOG_DIR, "aegis_events.jsonl"), "a") as f:
        f.write(json.dumps(entry) + "\n")

@dataclass
class Threat:
    ip: str
    kind: str
    severity: int
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    recommendation: str = "monitor"

class PolicyEngine:
    SAFE_AUTONOMOUS = {
        "STATUS",
        "HELP",
        "run_THREAT",
        "QUANTUM_SCAN",
        "PREDICT",
        "REPORT",
        "ENTROPY",
        "SYSTEM_ANALYSIS"
    }

    REQUIRES_MANUAL = {
        "FIREWALL_BLOCK",
        "SYSTEM_MODIFY",
        "SHUTDOWN"
    }

    def evaluate(self, intent: str) -> Dict[str, Any]:
        if intent in self.REQUIRES_MANUAL:
            return {"allowed": False, "reason": "manual authorization required"}
        return {"allowed": intent in self.SAFE_AUTONOMOUS, "reason": "autonomous mode"}

class QuantumSecuritySimulator:
    def __init__(self):
        self.threats: List[Threat] = []

    def scan(self, payload: Dict[str, Any]):
        ip = payload.get("ip", "127.0.0.1")
        port = int(payload.get("port", random.choice([22,80,443,8333,3389])))
        crypto_ports = {8332,8333,18332,18333,30303,9735,18080,18081}

        if port in crypto_ports:
            kind = "CRYPTO_ACTIVITY"
            severity = 7
        elif port in {22,23,3389}:
            kind = "REMOTE_ACCESS_PROBE"
            severity = 6
        else:
            kind = "NETWORK_ACTIVITY"
            severity = 3

        confidence = round(random.uniform(0.72, 0.99), 3)
        recommendation = "isolate_in_lab" if severity >= 7 else "monitor"
        threat = Threat(ip, kind, severity, confidence, recommendation=recommendation)
        self.threats.append(threat)
        log("quantum_scan", threat.__dict__)
        return threat.__dict__

    def run_attack(self):
        samples = [
            {"ip": "10.0.0.50", "port": 8333},
            {"ip": "192.168.1.100", "port": 22},
            {"ip": "203.0.113.10", "port": 80},
            {"ip": "172.16.0.20", "port": 30303},
        ]
        return [self.scan(x) for x in samples]

class PredictiveModule:
    def run(self):
        X = np.array([[0,0],[1,1],[2,1],[8,9],[9,8],[10,10]])
        y = np.array([0,0,0,1,1,1])
        model = RandomForestClassifier(n_estimators=50, random_state=42)
        model.fit(X, y)
        test = np.array([[7,8],[1,0]])
        pred = model.predict(test).tolist()
        result = {"input": test.tolist(), "prediction": pred, "label": "1=high_risk"}
        log("predictive_model", result)
        return result

class SystemAnalyzer:
    def run(self):
        result = {
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": psutil.virtual_memory().percent,
            "logical_cpus": psutil.cpu_count(logical=True),
            "physical_cpus": psutil.cpu_count(logical=False),
            "boot_time": psutil.boot_time(),
            "note": "System analysis completed."
        }
        log("system_analysis", result)
        return result

class EntropyModule:
    def run(self):
        key = Fernet.generate_key()
        digest = hashlib.sha512(key).hexdigest()
        result = {
            "fernet_key_generated": True,
            "sha512_digest_preview": digest[:32] + "...",
            "note": "Demo entropy only; not claiming quantum randomness."
        }
        log("entropy_demo", result)
        return result

class CommandRouter:
    def parse(self, cmd: str):
        c = cmd.lower().strip()
        if c in {"help", "?"}: return "HELP", {}
        if c in {"status", "system status"}: return "STATUS", {}
        if "run" in c and "threat" in c: return "run_THREAT", {}
        if "quantum" in c or "scan" in c:
            payload = {}
            for token in c.split():
                if token.count(".") == 3:
                    payload["ip"] = token
                if token.isdigit():
                    payload["port"] = int(token)
            return "QUANTUM_SCAN", payload
        if "predict" in c: return "PREDICT", {}
        if "report" in c: return "REPORT", {}
        if "entropy" in c or "key" in c: return "ENTROPY", {}
        if "analyze system" in c or "system analysis" in c: return "SYSTEM_ANALYSIS", {}
        if "block" in c or "firewall" in c: return "FIREWALL_BLOCK", {}
        if "shutdown" in c: return "SHUTDOWN", {}
        return "UNKNOWN", {}

class Orchestrator:
    def __init__(self):
        self.policy = PolicyEngine()
        self.router = CommandRouter()
        self.quantum = QuantumSecuritySimulator()
        self.predictor = PredictiveModule()
        self.system = SystemAnalyzer()
        self.entropy = EntropyModule()

    def execute(self, cmd: str):
        intent, payload = self.router.parse(cmd)
        decision = self.policy.evaluate(intent)

        if intent == "UNKNOWN":
            return {"status": "unknown", "hint": "type help"}

        if not decision["allowed"]:
            return {
                "status": "blocked_by_policy",
                "intent": intent,
                "reason": decision["reason"],
                "note": "This all-in-one script runs in autonomous mode."
            }

        if intent == "HELP":
            return self.help()
        if intent == "STATUS":
            return {"status": "AEGIS OMNI-XEON AUTONOMOUS MODE ACTIVE"}
        if intent == "run_THREAT":
            return self.quantum.run_attack()
        if intent == "QUANTUM_SCAN":
            return self.quantum.scan(payload)
        if intent == "PREDICT":
            return self.predictor.run()
        if intent == "SYSTEM_ANALYSIS":
            return self.system.run()
        if intent == "ENTROPY":
            return self.entropy.run()
        if intent == "REPORT":
            return self.report()

    def help(self):
        return {
            "commands": [
                "status",
                "analyze system",
                "run threat",
                "quantum scan 10.0.0.50 8333",
                "predict",
                "entropy",
                "report",
                "help"
            ],
            "blocked_for_safety": [
                "automatic firewall block",
                "stealth/cloaking",
                "persistence",
                "destructive system modification"
            ]
        }

    def report(self):
        table = Table(title="AEGIS OMNI-XEON Report")
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Threats observed", str(len(self.quantum.threats)))
        table.add_row("Mode", "Autonomous local analysis")
        table.add_row("Logs", os.path.join(LOG_DIR, "aegis_events.jsonl"))
        console.print(table)
        return {"report": "displayed", "log": os.path.join(LOG_DIR, "aegis_events.jsonl")}

def main():
    console.print("[bold cyan]AEGIS OMNI-XEON Core vΩ[/bold cyan]")
    console.print("Autonomous execution shell. Type [bold]help[/bold]. Type [bold]exit[/bold] to quit.")
    orch = Orchestrator()
    while True:
        try:
            cmd = input("AEGIS> ").strip()
            if cmd.lower() in {"exit", "quit"}:
                print("Exiting.")
                break
            result = orch.execute(cmd)
            console.print_json(json.dumps(result, default=str))
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        except Exception as e:
            log("error", {"error": str(e)})
            console.print({"error": str(e)})

if __name__ == "__main__":
    main()
