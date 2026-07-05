#!/bin/bash
# Week-long serve soak: run against a long-lived cluster and check tune output
# plus memory/state-file growth after several days.
#   ./contrib/soak.sh &   (or a systemd unit)
set -e
mkdir -p ~/deadair-soak
exec deadair serve \
  --interval 5m \
  --state-file ~/deadair-soak/state.json \
  --schema \
  2>> ~/deadair-soak/serve.log
