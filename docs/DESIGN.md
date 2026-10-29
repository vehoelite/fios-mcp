# Design

## Layers

```
fios_mcp/
  server.py      MCP tools (official `mcp` SDK, stdio only). No HTTP here.
  service.py     The change gate: validation, preview, etag, confirm, read-back.
  policy.py      Owner guard-rails from policy.toml.
  snapshot.py    Snapshots, keyed diffs, desired-state drift.
  config.py      Router URL, password file, pinned cert, policy path.
  cli.py         serve | trust | check
  models.py      Backend-neutral pydantic models.
  redact.py      Removes Wi-Fi keys / passwords from everything returned.
  backend/stock/
    transport.py One serialised HTTP session: pinned TLS, throttled login, logout on close.
    auth.py      The web UI's login hashing.
    jsparse.py   Parses the router's JavaScript responses without executing them.
    backend.py   One method per feature, each following a recipe verified on hardware.
```

A future OpenWrt backend (the CR1000A has community OpenWrt builds) would sit
beside `stock/` and keep the same tool names.

## Writes are two-phase

Every mutating tool goes through `Service._change`:

1. read the current state and hash it (`state_etag`);
2. validate against the router's real rules and `policy.toml`;
3. without `confirm`: return a preview, the etag, and a note to show it to the user;
4. with `confirm` and the preview's `expected_etag`: re-read, refuse on any
   change since the preview (`conflict` — e.g. an edit in the web UI), write,
   read back, and return `verified: true|false`.

Identical requests return `result: "no_change"` without writing.

## Fail-closed

- Writes are refused on firmware versions not in `VERIFIED_FIRMWARE` unless
  `FIOS_MCP_ALLOW_UNVERIFIED_FIRMWARE=1`.
- Every write uses field ids from a fresh read; a missing field (page changed
  shape) aborts the write.
- Statements in router responses that are not plain literals are skipped and
  counted, never executed.

## Refused entirely

Factory reset, firmware upgrade, admin password changes and enabling remote
administration have no tools: one-off, high-blast-radius operations better
done in the web UI. Moving the LAN (`set_lan_settings`) exists but is off
unless `policy.toml` sets `allow_lan_change = true`; because the router moves,
it reports the new address instead of a read-back.

## Session discipline

The router allows `session_max` (default 10) concurrent sessions and expires
them after `session_timeout` (600 s). The transport keeps one session per
process, re-logs in only when the router says the session is gone, throttles
logins (≥2 s apart, ≤5 per 10 min) and logs out on close.

## Testing

- `tests/mock_router.py` imitates the router's behaviour and quirks;
  `tests/test_tools.py` drives the real tool functions through it.
- `tests/contract/bench_e2e.py` runs every tool over stdio MCP against a real
  router on an isolated bench (opt-in; see the README).
- `tests/test_no_leaks.py` keeps real MACs, public IPs and a private denylist
  out of the repository.
