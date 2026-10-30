"""Rule registry. Adding a detection = one import + one entry in RULES."""
from __future__ import annotations

from detector.rules.base import Rule
from detector.rules.ssh_bruteforce import SshBruteForce
from detector.rules.valid_after_bruteforce import SshValidAfterBruteForce

RULES: list[Rule] = [
    SshBruteForce(),
    SshValidAfterBruteForce(),
]
