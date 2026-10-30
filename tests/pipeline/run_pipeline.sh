#!/usr/bin/env bash
# make pipeline: inject each scenario's raw SSH lines into syslog-raw and poll
# Postgres for the expected alerts (SPEC Testing level 2).
#
# Requires the stack to be up (docker compose up -d) so the detector and
# storage-writer are running. Each run uses a fresh random /16 so detector
# in-memory state and leftover alert rows never contaminate the result.
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2
DC="docker compose"
PGUSER="${POSTGRES_USER:-siem}"
PGDB="${POSTGRES_DB:-siem}"
TIMEOUT="${PIPELINE_TIMEOUT:-15}"

# Fresh base IP per run (valid IPv4, unique source state).
A=$(( (RANDOM % 250) + 1 )); B=$(( (RANDOM % 250) + 1 ))
BASE="10.${A}.${B}"

pass=0; fail=0

psql() { $DC exec -T postgres psql -U "$PGUSER" -d "$PGDB" -tAc "$1" 2>/dev/null; }

wait_for_tech() {   # ip tech  -> 0 if seen within TIMEOUT
  local ip="$1" tech="$2" end=$(( SECONDS + TIMEOUT ))
  while [ "$SECONDS" -lt "$end" ]; do
    [ "$(psql "select 1 from alerts where source_ip='${ip}' and technique='${tech}' limit 1")" = "1" ] && return 0
    sleep 1
  done
  return 1
}

techs_for_ip() { psql "select distinct technique from alerts where source_ip='${1}' order by 1" | tr '\n' ' '; }

check() {   # name scenario octet "present..." "absent..."
  local name="$1" scenario="$2" octet="$3" present="$4" absent="$5"
  local ip="${BASE}.${octet}"
  echo "--- ${name} (${scenario}) ip=${ip}"
  $DC run --rm injector "$scenario" --ip "$ip" >/dev/null 2>&1

  local ok=1
  for tech in $present; do
    if wait_for_tech "$ip" "$tech"; then echo "    present: ${tech} OK"
    else echo "    present: ${tech} MISSING"; ok=0; fi
  done
  # For controls (no expected alerts) give the pipeline time before asserting none.
  [ -z "$present" ] && sleep "$TIMEOUT"
  local seen; seen="$(techs_for_ip "$ip")"
  for tech in $absent; do
    if echo " ${seen} " | grep -q " ${tech} "; then echo "    absent:  ${tech} UNEXPECTEDLY PRESENT"; ok=0
    else echo "    absent:  ${tech} OK"; fi
  done
  echo "    alerts for ip: [${seen}]"
  if [ "$ok" = 1 ]; then pass=$((pass+1)); echo "    => PASS"; else fail=$((fail+1)); echo "    => FAIL"; fi
}

echo "Building injector image..."
$DC build injector >/dev/null 2>&1 || { echo "injector build failed"; exit 2; }

echo "Running pipeline scenarios (base ${BASE}.x, timeout ${TIMEOUT}s each)"
check "A1 bruteforce-fail"    bruteforce-fail     11 "T1110.001"        "T1078 T1110.003"
check "A2 bruteforce-success" bruteforce-success  12 "T1110.001 T1078"  ""
check "A3 password-spray"     password-spray      13 "T1110.003"        "T1110.001"
check "C1 normal-typo"        normal-typo         21 ""                 "T1110.001 T1110.003 T1078"
check "C2 slow-guess"         slow-guess          22 ""                 "T1110.001 T1110.003 T1078"

echo "============================================================"
echo "pipeline: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
