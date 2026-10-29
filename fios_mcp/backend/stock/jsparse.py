"""Parse the CR1000A's `cgi/cgi_<page>.js` responses without executing them.

The router answers config reads with JavaScript that its web UI `eval()`s:

    addCfg("route_ipv4_ipaddr0", "<opaque id>", "0.0.0.0");
    addROD("rTable", "[ '192.168.1.0','255.255.255.0', ... ]");
    // port rule (for ACL, port forwarding, static NAT)
    addROD("portrules", { "portrules": [ { "id": 1, ... }, ] });

The literals are JavaScript, not JSON: single-quoted strings, trailing commas,
array holes, bare object keys, comments, and arrays nested inside strings.
This module is a small literal parser for exactly that subset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_KNOWN_CALLS = {"addCfg", "addROD"}


class JsParseError(ValueError):
    def __init__(self, msg: str, pos: int):
        super().__init__(f"{msg} at offset {pos}")
        self.pos = pos


@dataclass(frozen=True)
class CfgField:
    name: str
    id: str  # opaque per-field key used when writing via apply_abstract.cgi
    value: str
    extra: Any = None


@dataclass
class CgiData:
    cfg: dict[str, CfgField] = field(default_factory=dict)
    rod: dict[str, Any] = field(default_factory=dict)
    unknown_calls: list[str] = field(default_factory=list)
    # Statements that are real JavaScript (e.g. `parseInt(...)`) rather than literals.
    skipped: list[str] = field(default_factory=list)

    def value(self, name: str, default: str = "") -> str:
        f = self.cfg.get(name)
        return f.value if f else default


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0

    # -- low level ---------------------------------------------------------

    def _skip(self) -> None:
        s, n = self.s, len(self.s)
        while self.i < n:
            c = s[self.i]
            if c in " \t\r\n﻿":
                self.i += 1
            elif s.startswith("//", self.i):
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end + 1
            elif s.startswith("/*", self.i):
                end = s.find("*/", self.i + 2)
                if end < 0:
                    raise JsParseError("unterminated comment", self.i)
                self.i = end + 2
            else:
                return

    def _peek(self) -> str:
        self._skip()
        return self.s[self.i] if self.i < len(self.s) else ""

    def _expect(self, ch: str) -> None:
        if self._peek() != ch:
            raise JsParseError(f"expected {ch!r}, got {self._peek()!r}", self.i)
        self.i += 1

    def _ident(self) -> str:
        self._skip()
        start = self.i
        while self.i < len(self.s) and (self.s[self.i].isalnum() or self.s[self.i] in "_$"):
            self.i += 1
        if start == self.i:
            raise JsParseError("expected identifier", self.i)
        return self.s[start:self.i]

    # -- literals ----------------------------------------------------------

    def literal(self) -> Any:
        c = self._peek()
        if c in "\"'":
            return self._string()
        if c == "[":
            return self._array()
        if c == "{":
            return self._object()
        if c == "-" or c.isdigit() or c == ".":
            return self._number()
        word = self._ident()
        if word == "true":
            return True
        if word == "false":
            return False
        if word in ("null", "undefined"):
            return None
        raise JsParseError(f"unexpected identifier {word!r} in literal", self.i)

    def _string(self) -> str:
        quote = self.s[self.i]
        self.i += 1
        out: list[str] = []
        s, n = self.s, len(self.s)
        while self.i < n:
            c = s[self.i]
            if c == quote:
                self.i += 1
                return "".join(out)
            if c == "\\":
                self.i += 1
                if self.i >= n:
                    break
                e = s[self.i]
                if e == "u":
                    out.append(chr(int(s[self.i + 1:self.i + 5], 16)))
                    self.i += 5
                    continue
                if e == "x":
                    out.append(chr(int(s[self.i + 1:self.i + 3], 16)))
                    self.i += 3
                    continue
                out.append({"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
                            "v": "\v", "0": "\0"}.get(e, e))
                self.i += 1
                continue
            out.append(c)
            self.i += 1
        raise JsParseError("unterminated string", self.i)

    def _number(self) -> int | float:
        start = self.i
        if self.s[self.i] == "-":
            self.i += 1
        while self.i < len(self.s) and (self.s[self.i].isalnum() or self.s[self.i] in ".+-"):
            if self.s[self.i] in "+-" and self.s[self.i - 1] not in "eE":
                break
            self.i += 1
        text = self.s[start:self.i]
        try:
            if text.lower().startswith(("0x", "-0x")):
                return int(text, 16)
            return int(text) if text.lstrip("-").isdigit() else float(text)
        except ValueError as exc:
            raise JsParseError(f"bad number {text!r}", start) from exc

    def _array(self) -> list[Any]:
        self._expect("[")
        out: list[Any] = []
        while True:
            c = self._peek()
            if c == "]":
                self.i += 1
                return out
            if c == ",":  # hole: [1,,2]
                self.i += 1
                out.append(None)
                continue
            out.append(self.literal())
            c = self._peek()
            if c == ",":
                self.i += 1
            elif c != "]":
                raise JsParseError("expected ',' or ']'", self.i)

    def _object(self) -> dict[str, Any]:
        self._expect("{")
        out: dict[str, Any] = {}
        while True:
            c = self._peek()
            if c == "}":
                self.i += 1
                return out
            if c in "\"'":
                key = self._string()
            elif c.isdigit():
                key = str(self._number())
            else:
                key = self._ident()
            self._expect(":")
            out[key] = self.literal()
            c = self._peek()
            if c == ",":
                self.i += 1
            elif c != "}":
                raise JsParseError("expected ',' or '}'", self.i)

    # -- statements --------------------------------------------------------

    def _call(self) -> tuple[str, list[Any]]:
        name = self._ident()
        self._expect("(")
        args: list[Any] = []
        while self._peek() != ")":
            args.append(self.literal())
            if self._peek() == ",":
                self.i += 1
        self._expect(")")
        return name, args

    def calls(self, skipped: list[str] | None = None) -> list[tuple[str, list[Any]]]:
        out = []
        while self._peek():
            if self._peek() == ";":
                self.i += 1
                continue
            start = self.i
            try:
                out.append(self._call())
            except JsParseError:
                if skipped is None:
                    raise
                # Not a literal call: skip to the end of this statement and record it.
                end = self.s.find(");", start)
                self.i = len(self.s) if end < 0 else end + 2
                skipped.append(self.s[start:self.i][:80])
        return out


def parse_literal(text: str) -> Any:
    p = _Parser(text)
    value = p.literal()
    if p._peek():
        raise JsParseError("trailing data after literal", p.i)
    return value


def _maybe_nested(value: Any) -> Any:
    """`addROD("rTable", "[ '203.0.113.4', ... ]")` carries an array inside a string."""
    if isinstance(value, str) and value.strip()[:1] in ("[", "{"):
        try:
            return parse_literal(value)
        except JsParseError:
            return value
    return value


def parse_cgi(text: str) -> CgiData:
    data = CgiData()
    for name, args in _Parser(text).calls(data.skipped):
        if name == "addCfg" and len(args) >= 3:
            cfg_name, cfg_id, value = args[0], args[1], args[2]
            extra = args[3] if len(args) > 3 else None
            data.cfg[str(cfg_name)] = CfgField(str(cfg_name), str(cfg_id), str(value), extra)
        elif name == "addROD" and len(args) >= 2:
            data.rod[str(args[0])] = _maybe_nested(args[1])
        else:
            data.unknown_calls.append(name)
    return data


def known_calls() -> set[str]:
    return set(_KNOWN_CALLS)
