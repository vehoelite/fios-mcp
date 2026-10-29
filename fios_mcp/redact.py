"""Keep Wi-Fi keys and admin passwords out of tool output.

Several router pages return credentials in clear text (e.g. `sharedkey24G`,
`guest_password`, `user_userPass`). Anything whose name looks secret is
replaced before it can reach a model, a log or a fixture.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "***REDACTED***"
_SECRET = re.compile(r"(pass|psk|sharedkey|secret|passphrase|wpa_?key|wep_?key|_pin$|^pin$|token|userpass)",
                     re.IGNORECASE)


def is_secret_name(name: str) -> bool:
    return bool(_SECRET.search(name))


def redact(value: Any, name: str = "") -> Any:
    if name and is_secret_name(name) and value not in ("", None, [], {}):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
