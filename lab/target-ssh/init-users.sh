#!/usr/bin/with-contenv bash
# Runs once at container start (linuxserver /custom-cont-init.d hook).
# Creates the normal SSH accounts traffic-gen uses, all with the same strong
# password. The weak `admin` account is created by the image from USER_NAME /
# USER_PASSWORD, so it is not touched here.
set -eu

normal_users="${NORMAL_USERS:-}"
normal_password="${NORMAL_PASSWORD:-}"

if [ -z "$normal_users" ] || [ -z "$normal_password" ]; then
  echo "[init-users] NORMAL_USERS or NORMAL_PASSWORD unset; no extra users created"
  exit 0
fi

# NORMAL_USERS is a comma-separated list, e.g. "alice,bob,carol".
IFS=','
for username in $normal_users; do
  username="$(echo "$username" | tr -d '[:space:]')"
  [ -z "$username" ] && continue
  if id "$username" >/dev/null 2>&1; then
    echo "[init-users] user $username already exists"
  else
    adduser -D -s /bin/false "$username"
    echo "[init-users] created user $username"
  fi
  echo "${username}:${normal_password}" | chpasswd
done

echo "[init-users] done"
