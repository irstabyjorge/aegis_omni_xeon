# AEGIS OMNI-XEON

**Autonomous Security Monitoring & Threat Intelligence Platform**

AEGIS OMNI-XEON is a real-time security monitoring suite built in Python. It provides system analysis, network threat detection, authentication log auditing, firewall inspection, and predictive threat modeling -- all from a single unified command-line interface.

---

## Features

- **Real-time System Monitoring** -- CPU, memory, disk, boot time, process inspection
- **QByte-22 Threat Engine** -- Real IP threat scoring with 50+ signal vectors (Tor exits, scanner nets, threat intel, bogon ranges)
- **Network Threat Scanner** -- Detects suspicious ports, high-frequency remote connections, and crypto-mining activity
- **Auto-Blocklisting** -- Automatically blocks high-threat IPs with persistent blocklist database
- **Authentication Log Auditor** -- Parses auth.log and syslog for failed logins, privilege escalation, and session anomalies
- **Firewall Inspector** -- Reports UFW and iptables status at a glance
- **Predictive Threat Modeling** -- ML-based risk classification using scikit-learn
- **Entropy & Key Generation** -- Fernet key generation with SHA-512 digest verification
- **Continuous Watch Mode** -- Automated threat scanning on a 10-second loop
- **Structured Event Logging** -- All events logged as JSONL for forensic review
- **Policy Engine** -- Separates safe autonomous operations from actions requiring manual authorization

## Modes

| Mode | Script | Purpose |
|------|--------|---------|
| **OMNI-XEON** | `aegis_omni.py` | Full autonomous security operations with QByte-22 engine and ML prediction |
| **Real System** | `aegis_real.py` | Live system monitoring with real network/auth data |
| **Unified** | `aegis_unified.py` | Production platform combining all capabilities |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/irstabyjorge/aegis_omni_xeon.git
cd aegis_omni_xeon

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the unified system
python3 aegis_unified.py
```

## Commands (Unified Mode)

```
status           -- System health overview
listeners        -- Show listening ports with risk flags
connections      -- Show active connections
threats          -- Scan live connections with QByte-22 engine
scan <ip> [port] -- Analyze specific IP threat level
auth             -- Audit authentication logs
firewall         -- Show firewall rules and status
packages         -- List installed packages
entropy          -- Generate cryptographic key material
blocklist        -- Show auto-blocked IPs
all              -- Run full security audit
watch            -- Continuous threat monitoring (10s interval)
logs             -- View recent event log
help             -- Show available commands
exit             -- Quit
```

## Requirements

- Python 3.10+
- Linux (Ubuntu/Debian recommended)
- Root/sudo access for full auth log and firewall inspection

## Dependencies

```
numpy
scikit-learn
rich
psutil
cryptography
```

## Modules

### API Server (`modules/api_server.py`)
REST API exposing all AEGIS capabilities over HTTP. Zero external dependencies — built on Python's `http.server`. Endpoints for threat scanning, connection monitoring, log analysis, entropy generation, uptime checks, and predictive modeling.

```bash
# Start the API server (default port 8443)
python3 -m modules.api_server

# Or set a custom port
AEGIS_PORT=9000 python3 -m modules.api_server
```

**Endpoints:**
| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | System health overview |
| `GET /api/threats` | Scan live connections with QByte-22 |
| `GET /api/scan/<ip>` | Analyze specific IP threat level |
| `GET /api/connections` | Active network connections |
| `GET /api/listeners` | Listening ports with risk flags |
| `GET /api/entropy` | Generate cryptographic key material |
| `GET /api/blocklist` | Auto-blocked IP list |
| `GET /api/uptime` | Service availability report |
| `GET /api/logs/analysis` | System log security analysis |
| `GET /api/logs/threats` | AEGIS threat log analysis |
| `GET /api/predict` | ML-based threat prediction |

### Log Analyzer (`modules/log_analyzer.py`)
Pattern-based security log analysis engine. Scans system logs (`auth.log`, `syslog`, `kern.log`, `ufw.log`) for attack signatures including brute force attempts, privilege escalation, SSH scanning, suspicious commands, account changes, and firewall modifications.

```bash
# Analyze system logs
python3 -m modules.log_analyzer

# Analyze AEGIS threat history
python3 -m modules.log_analyzer threats
```

### Uptime Monitor (`modules/uptime_monitor.py`)
Service availability tracking with HTTP endpoint monitoring, TCP port checks, DNS resolution verification, and SSL certificate expiry warnings.

```bash
# Run a single check
python3 -m modules.uptime_monitor

# Continuous monitoring (every 30 seconds)
python3 -m modules.uptime_monitor watch
```

### Vulnerability Scanner (`modules/vuln_scanner.py`)
Local system security assessment. Checks SUID files, world-writable files, SSH configuration, firewall status, auto-updates, exposed ports, sensitive file permissions, root execution, and kernel hardening (ASLR, ptrace, core dumps).

```bash
python3 -m modules.vuln_scanner
```

Produces a security score (0-10) with findings categorized as critical, warning, or passed.

## Project Structure

```
aegis_omni_xeon/
    aegis_omni.py          # OMNI-XEON -- full autonomous security with QByte-22 + ML
    aegis_real.py          # Real system -- live network/auth/firewall monitoring
    aegis_unified.py       # Unified -- production platform combining all modules
    requirements.txt       # Python dependencies
    pyproject.toml         # Package metadata
    config/                # Configuration files
    data/                  # Blocklists, known-good IPs, runtime data
    logs/                  # JSONL event logs and threat logs
    modules/
        __init__.py
        api_server.py      # REST API server
        log_analyzer.py    # Security log analysis engine
        uptime_monitor.py  # Service availability monitoring
        vuln_scanner.py    # Vulnerability assessment scanner
```

## Logging

All events are logged to `logs/` as JSONL files with timestamps, event types, and full payloads. These logs are designed for forensic analysis and can be ingested by any SIEM or log aggregation tool.

## License

This software is dual-licensed:

- **Personal & Academic Use**: Free under the [MIT License](LICENSE)
- **Commercial Use**: Requires a commercial license. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)

### Commercial Licensing

| Tier | Monthly | Annual | Users |
|------|---------|--------|-------|
| Professional | $2,499 | $29,988 | Up to 10 |
| Business | $9,999 | $119,988 | Up to 50 |
| Enterprise | $24,999 | $299,988 | Unlimited |
| Enterprise Plus | $49,999 | $599,988 | Unlimited |
| Sovereign / Gov | $99,999 | $1,199,988 | Unlimited |

Multi-year discounts available (up to 40% off). Contact IRSTAXBYJORGE@GMAIL.COM for licensing.

## Author

**Jorge Francisco Paredes** (irstabyjorge)

- GitHub: [github.com/irstabyjorge](https://github.com/irstabyjorge)
- Email: IRSTAXBYJORGE@GMAIL.COM

---

### Support This Project

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-GitHub-ea4aaa?logo=github)](https://github.com/sponsors/irstabyjorge)

If you use AEGIS in your work, consider sponsoring the project to support continued development.

---

Copyright (c) 2024-2026 Jorge Francisco Paredes. All rights reserved.
