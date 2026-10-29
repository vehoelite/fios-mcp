import pytest

from fios_mcp.backend.stock.jsparse import JsParseError, parse_cgi, parse_literal

SAMPLE = """
addCfg("net_name", "aWQx+/=", "Network (Home/Office)");
addROD("rTable",  "[ '192.168.1.0','255.255.255.0','0.0.0.0','0','LAN']");
addROD("routes6_Table",  "[]");

addCfg("route_ipv4_idxen0", "aWQy==", "0");
// port rule (for ACL, port forwarding, static NAT)
addROD("portrules", { "portrules": [ { "id": 1, "name": "FTP", "ports": [ { "id": 1, }, ] }, ] });
addROD("upnpportforwardings", [null]);
addROD("reservePort", [4577,4567,]);
addROD("dump_dhcp_leases", [ ['host-a','192.168.1.10','02:00:00:00:00:01','85449']] );
/* block comment */ addCfg("quoted", "aWQz", "say \\"hi\\" \\u00e9");
"""


def test_parses_cfg_fields_with_ids():
    d = parse_cgi(SAMPLE)
    assert d.cfg["net_name"].id == "aWQx+/="
    assert d.value("net_name") == "Network (Home/Office)"
    assert d.value("route_ipv4_idxen0") == "0"
    assert d.value("quoted") == 'say "hi" é'
    assert d.value("missing", "x") == "x"


def test_nested_array_inside_string_is_parsed():
    d = parse_cgi(SAMPLE)
    assert d.rod["rTable"] == ["192.168.1.0", "255.255.255.0", "0.0.0.0", "0", "LAN"]
    assert d.rod["routes6_Table"] == []


def test_trailing_commas_holes_comments_and_single_quotes():
    d = parse_cgi(SAMPLE)
    assert d.rod["portrules"]["portrules"][0]["ports"] == [{"id": 1}]
    assert d.rod["upnpportforwardings"] == [None]
    assert d.rod["reservePort"] == [4577, 4567]
    assert d.rod["dump_dhcp_leases"][0][2] == "02:00:00:00:00:01"
    assert d.unknown_calls == []


def test_unknown_calls_are_reported_not_ignored():
    d = parse_cgi('addCfg("a","b","c"); somethingNew("x");')
    assert d.unknown_calls == ["somethingNew"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("{a: 1, 'b': [1,,2], \"c\": {d: true}}", {"a": 1, "b": [1, None, 2], "c": {"d": True}}),
        ("[-1, 2.5, 0x10, undefined, false]", [-1, 2.5, 16, None, False]),
    ],
)
def test_literals(text, expected):
    assert parse_literal(text) == expected


def test_never_executes_and_skips_non_literal_statements():
    d = parse_cgi('addCfg("a", "b", window.location);\naddCfg("ok", "id", "1");')
    assert "a" not in d.cfg
    assert d.value("ok") == "1"
    assert d.skipped and d.skipped[0].startswith('addCfg("a"')
    with pytest.raises(JsParseError):
        parse_literal("'unterminated")
