"""Login hashing used by the CR1000A web UI.

Read from the UI's own JavaScript (`login_encode`, `do_encode`, `ArcMD5` in
`js/app.<hash>.js`) and verified against a real router.

    ArcMD5(x)      = SHA512hex(MD5hex(x))
    luci_username  = ArcMD5(username)
    luci_password  = SHA512hex(loginToken + ArcMD5(password))   (ArcMD5(password) if no token)
"""

from __future__ import annotations

import hashlib


def md5hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha512hex(text: str) -> str:
    return hashlib.sha512(text.encode("utf-8")).hexdigest()


def arc_md5(text: str) -> str:
    return sha512hex(md5hex(text))


def encode_username(username: str) -> str:
    return arc_md5(username)


def encode_password(password: str, login_token: str) -> str:
    if not login_token:
        return arc_md5(password)
    return sha512hex(login_token + arc_md5(password))


def login_form(username: str, password: str, login_token: str, *, keep: bool = False) -> dict[str, str]:
    return {
        "luci_username": encode_username(username),
        "luci_password": encode_password(password, login_token),
        "luci_view": "Desktop",
        "luci_token": login_token,
        "luci_keep_login": "1" if keep else "0",
    }
