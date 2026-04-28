# AEGIS OMNI-XEON

**Autonomous Security Monitoring & Threat Intelligence Platform**

AEGIS OMNI-XEON is a real-time security monitoring suite built in Python. It provides system analysis, network threat detection, authentication log auditing, firewall inspection, and predictive threat modeling -- all from a single unified command-line interface.

---

## Features

- **Real-time System Monitoring** -- CPU, memory, disk, boot time, process inspection
- **Network Threat Scanner** -- Detects suspicious ports, high-frequency remote connections, and crypto-mining activity
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
| **Simulation** | `aegis_omni.py` | Threat simulation and predictive modeling sandbox |
| **Real System** | `aegis_real.py` | Live system monitoring with actual network/auth data |
| **Unified** | `aegis_unified.py` | Full-featured production mode combining all capabilities |

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
status        -- System health overview
listeners     -- Show listening network services
connections   -- Show active network connections
threats       -- Run threat scan on all connections
auth          -- Audit authentication logs
firewall      -- Show firewall rules and status
packages      -- List installed packages
entropy       -- Generate cryptographic key material
all           -- Run full security audit
watch         -- Continuous threat monitoring (10s interval)
logs          -- View recent event log
help          -- Show available commands
exit          -- Quit
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

## Project Structure

```
aegis_omni_xeon/
    aegis_omni.py          # Simulation mode -- threat modeling sandbox
    aegis_real.py          # Real system mode -- live monitoring
    aegis_unified.py       # Unified mode -- full production suite
    requirements.txt       # Python dependencies
    config/                # Configuration files
    data/                  # Runtime data
    logs/                  # JSONL event logs (auto-generated)
    modules/               # Extension modules
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
