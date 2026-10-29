import hashlib

from fios_mcp.backend.stock.auth import arc_md5, encode_password, login_form


def _sha512(s: str) -> str:
    return hashlib.sha512(s.encode()).hexdigest()


def test_arc_md5_is_sha512_of_md5_hex():
    assert arc_md5("admin") == _sha512(hashlib.md5(b"admin").hexdigest())


def test_password_is_salted_with_login_token():
    assert encode_password("pw", "TOKEN") == _sha512("TOKEN" + arc_md5("pw"))
    assert encode_password("pw", "") == arc_md5("pw")
    assert encode_password("pw", "A") != encode_password("pw", "B")


def test_login_form_never_contains_the_plain_password():
    form = login_form("admin", "s3cret-pass", "TOK")
    assert "s3cret-pass" not in "".join(form.values())
    assert form["luci_token"] == "TOK"
    assert set(form) == {"luci_username", "luci_password", "luci_view", "luci_token", "luci_keep_login"}
