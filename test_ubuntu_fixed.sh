#!/usr/bin/env bash
set -Eeuo pipefail
cd "$HOME/aegis_omni_xeon"
source .venv/bin/activate
export AUTHORIZED_USER="Jorge"
printf "status\nanalyze system\nrun threat\npredict\nentropy\nreport\nexit\n" | python "$HOME/aegis_omni_xeon/aegis_omni.py"
