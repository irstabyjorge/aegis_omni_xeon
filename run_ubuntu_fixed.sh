#!/usr/bin/env bash
set -Eeuo pipefail
cd "$HOME/aegis_omni_xeon"
source .venv/bin/activate
export AUTHORIZED_USER="Jorge"
python "$HOME/aegis_omni_xeon/aegis_omni.py"
