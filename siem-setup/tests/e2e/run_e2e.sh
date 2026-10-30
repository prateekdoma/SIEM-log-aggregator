#!/usr/bin/env bash
# make e2e: run the REAL attacker scenarios A1-A3 + C1-C2 against the lab and
# check GET /alerts after each (SPEC Testing level 3).
#
# The attacker hits the lab from one source IP and our cooldown is per
# (rule, technique, source.ip), so between scenarios we reset: truncate the
# alerts table and restart the detector (clearing its in-memory state/cooldowns),
# giving each scenario a clean slate. Needs the full stack up.
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2
DC="docker compose"
API="http://localhost:8000"
PGUSER="${POSTGRES_USER:-siem}"
PGDB="${POSTGRES_DB:-siem}"
WAIT="${E2E_ALERT_WAIT:-90}"

pass=0; fail=0

echo "Waiting for API /health ..."
for i in $(seq 1 24); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$API/health" 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 5
done
if [ "$(curl -s -o /dev/null -w '%{http_code}' "$API/health" 2>/dev/null)" != "200" ]; then
  echo "API not healthy at $API/health — is the stack up? (docker compose up -d --build)"; exit 2
fi

reset() {
  $DC exec -T postgres psql -U "$PGUSER" -d "$PGDB" -c "truncate alerts;" >/dev/null 2>&1
  $DC restart detector >/dev/null 2>&1
  sleep 8   # let both detector replicas rejoin the group with empty state
}

has_tech() { curl -s "$API/alerts?limit=200" | grep -q "\"technique\":\"$1\""; }

wait_tech() {   # tech [timeout] -> 0 if it shows up
  local tech="$1" end=$(( SECONDS + ${2:-$WAIT} ))
  while [ "$SECONDS" -lt "$end" ]; do has_tech "$tech" && return 0; sleep 3; done
  return 1
}

check() {   # name scenario "present..." "absent..."
  local name="$1" scenario="$2" present="$3" absent="$4"
  echo "--- ${name} (attack ${scenario})"
  reset
  $DC exec -T attacker attack "$scenario" >/dev/null 2>&1   # blocks until the scenario finishes
  local ok=1
  for tech in $present; do
    if wait_tech "$tech"; then echo "    present: ${tech} OK"
    else echo "    present: ${tech} MISSING"; ok=0; fi
  done
  [ -z "$present" ] && sleep 15          # controls: let the pipeline settle before asserting none
  for tech in $absent; do
    if has_tech "$tech"; then echo "    absent:  ${tech} UNEXPECTEDLY PRESENT"; ok=0
    else echo "    absent:  ${tech} OK"; fi
  done
  if [ "$ok" = 1 ]; then pass=$((pass+1)); echo "    => PASS"; else fail=$((fail+1)); echo "    => FAIL"; fi
}

echo "Running e2e scenarios (real attacker; ~5-10 min, C2 alone is 5 min)"
check "A1 bruteforce-fail"    bruteforce-fail     "T1110.001"       "T1078 T1110.003"
check "A2 bruteforce-success" bruteforce-success  "T1110.001 T1078" ""
check "A3 password-spray"     password-spray      "T1110.003"       "T1110.001"
check "C1 normal-typo"        normal-typo         ""                "T1110.001 T1110.003 T1078"
check "C2 slow-guess"         slow-guess          ""                "T1110.001 T1110.003 T1078"

echo "============================================================"
echo "e2e: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
