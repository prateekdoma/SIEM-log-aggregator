"""Normal background traffic for the lab.

Loops forever with random 2-20 s sleeps, doing one of two things each cycle:

  * SSH login as a random normal user with the correct password (paramiko),
    then disconnect. About 1 in 10 logins sends one wrong password first and
    then the right one (control C1 -- a typo, which must NOT alert).
  * HTTP GET of a normal DVWA page through target-web with a browser user agent.

This produces the baseline of successful SSH logins and web hits that the
pipeline normalizes; it never targets anything but the lab containers.
"""
from __future__ import annotations

import os
import random
import time

import paramiko
import requests

SSH_HOST = os.environ.get("SSH_HOST", "target-ssh")
SSH_PORT = int(os.environ.get("SSH_PORT", "2222"))
WEB_URL = os.environ.get("WEB_URL", "http://target-web").rstrip("/")

NORMAL_USERS = [
    user.strip()
    for user in os.environ.get("SSH_NORMAL_USERS", "").split(",")
    if user.strip()
]
NORMAL_PASSWORD = os.environ.get("SSH_NORMAL_PASS", "")

WRONG_PASSWORD = "definitely-not-the-password"

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
)

# Normal DVWA pages a logged-out browser would touch.
NORMAL_PATHS = [
    "/",
    "/login.php",
    "/setup.php",
    "/security.php",
    "/instructions.php",
    "/about.php",
]


def ssh_attempt(username: str, password: str) -> bool:
    """Make one SSH login attempt. Returns True on success, False on auth failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as exc:  # network hiccup, container still starting, etc.
        print(f"[traffic-gen] ssh error for {username}: {exc}", flush=True)
        return False
    finally:
        client.close()


def do_ssh_login() -> None:
    if not NORMAL_USERS or not NORMAL_PASSWORD:
        print("[traffic-gen] no normal users configured; skipping SSH", flush=True)
        return

    username = random.choice(NORMAL_USERS)

    # ~1 in 10: a single typo, then the correct password (control C1).
    if random.random() < 0.1:
        ssh_attempt(username, WRONG_PASSWORD)
        print(f"[traffic-gen] {username}: typo then retry", flush=True)

    ok = ssh_attempt(username, NORMAL_PASSWORD)
    outcome = "ok" if ok else "FAILED"
    print(f"[traffic-gen] ssh login {username}: {outcome}", flush=True)


def do_web_request() -> None:
    path = random.choice(NORMAL_PATHS)
    url = f"{WEB_URL}{path}"
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": BROWSER_USER_AGENT},
            timeout=10,
        )
        print(f"[traffic-gen] GET {path} -> {resp.status_code}", flush=True)
    except Exception as exc:
        print(f"[traffic-gen] web error for {path}: {exc}", flush=True)


def main() -> None:
    print(
        f"[traffic-gen] starting; users={NORMAL_USERS} ssh={SSH_HOST}:{SSH_PORT} "
        f"web={WEB_URL}",
        flush=True,
    )
    while True:
        if random.random() < 0.5:
            do_ssh_login()
        else:
            do_web_request()
        time.sleep(random.uniform(2, 20))


if __name__ == "__main__":
    main()
