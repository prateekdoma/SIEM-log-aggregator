#!/usr/bin/env bash
# Keeps the attacker container alive so scenarios can be run on demand with
# `docker compose exec attacker attack <scenario>`.
#
# If ATTACK_INTERVAL_MIN > 0, also runs A1-A3 on that interval for unattended
# demos. Default 0 = off (nothing runs until you call it).
set -euo pipefail

interval_min="${ATTACK_INTERVAL_MIN:-0}"

if [ "$interval_min" -gt 0 ] 2>/dev/null; then
  echo "[attacker] timed mode: A1-A3 every ${interval_min} min"
  while true; do
    attack bruteforce-fail    || true
    attack bruteforce-success || true
    attack password-spray     || true
    sleep "$(( interval_min * 60 ))"
  done
else
  echo "[attacker] idle; run: docker compose exec attacker attack <scenario>"
  exec sleep infinity
fi
