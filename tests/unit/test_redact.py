from fios_mcp.redact import REDACTED, redact


def test_redacts_secret_names_recursively():
    data = {
        "wl_ssid24G": "home",
        "sharedkey24G": "hunter22",
        "guest_password": "pw",
        "user_userPass": "x",
        "wps_pin": "1234",
        "nested": [{"iot_password": "y", "name": "ok"}],
        "empty_password": "",
    }
    out = redact(data)
    assert out["wl_ssid24G"] == "home"
    assert out["sharedkey24G"] == REDACTED
    assert out["guest_password"] == REDACTED
    assert out["user_userPass"] == REDACTED
    assert out["wps_pin"] == REDACTED
    assert out["nested"][0] == {"iot_password": REDACTED, "name": "ok"}
    assert out["empty_password"] == ""  # nothing to hide; keeps "is it set?" visible
