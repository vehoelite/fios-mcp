"""HTTP session with the CR1000A's local web interface.

One session, one lock: the router throttles logins and its web UI edits the
same config, so every request is serialised and the session is reused until
the router says it is gone.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

import httpx

from .auth import login_form
from .jsparse import CgiData, parse_cgi

log = logging.getLogger(__name__)

LOGIN_MIN_INTERVAL_S = 2.0
LOGIN_WINDOW_S = 600.0
LOGIN_MAX_PER_WINDOW = 5


class RouterError(RuntimeError):
    pass


class AuthError(RouterError):
    def __init__(self, msg: str, detail: dict[str, Any] | None = None):
        super().__init__(msg)
        self.detail = detail or {}


def explain_login_failure(detail: dict[str, Any]) -> str:
    """The 403 body of login.cgi, decoded the way the router's own UI does."""
    timeout = int(detail.get("timeout") or 0)
    flag = int(detail.get("flag") or 0)
    if flag == 7:
        return f"5 wrong passwords: login locked for {timeout}s"
    if timeout > 0:
        return f"login disabled by the router for {timeout}s"
    if flag == 1:
        return "wrong password"
    if flag == 2:
        return (f"too many open sessions (router allows {detail.get('maxsession', '?')}); "
                "wait for them to expire (10 min idle) or log out of the web UI")
    if flag in (3, 9):
        return "session expired"
    return f"router rejected the login ({detail or 'no detail'})"


class ThrottledError(RouterError):
    pass


class TlsPinError(RouterError):
    pass


@dataclass
class LoginStatus:
    logged_in: bool
    form_token: str
    login_token: str
    expires: int
    wizard_done: bool


def tls_context(pin_file: Path | None, *, insecure: bool = False) -> ssl.SSLContext | bool:
    """Trust exactly the pinned router certificate.

    The CR1000A presents a Verizon-CA certificate for `mynetworksettings.com`,
    so hostname checks against an IP can never pass; we pin the leaf instead.
    """
    if pin_file is not None:
        ctx = ssl.create_default_context(cafile=str(pin_file))
        ctx.check_hostname = False
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        return ctx
    if insecure:
        return False
    raise TlsPinError("no pinned router certificate; run `fios-mcp trust` first")


class RouterTransport:
    def __init__(
        self,
        base_url: str,
        password: str,
        *,
        username: str = "admin",
        verify: ssl.SSLContext | bool = True,
        timeout: float = 20.0,
        http_transport: httpx.AsyncBaseTransport | None = None,  # tests: an ASGI mock router
        login_min_interval: float = LOGIN_MIN_INTERVAL_S,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self._username = username
        self._password = password
        self._client = httpx.AsyncClient(
            base_url=self.base_url, verify=verify, timeout=timeout, follow_redirects=False,
            transport=http_transport,
        )
        self._lock = asyncio.Lock()
        self._form_token = ""
        self._logins: deque[float] = deque()
        self._login_min_interval = login_min_interval
        self.logins_performed = 0

    def __repr__(self) -> str:
        return f"RouterTransport({self.base_url!r}, password=***)"

    async def aclose(self) -> None:
        """Log out (the router caps concurrent sessions), then close the client."""
        try:
            await self.logout()
        except (httpx.HTTPError, RouterError):
            pass
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # -- session -----------------------------------------------------------

    async def _status(self) -> LoginStatus:
        r = await self._client.get("loginStatus.cgi")
        r.raise_for_status()
        d = r.json()
        return LoginStatus(
            logged_in=str(d.get("islogin")) == "1",
            form_token=str(d.get("token", "")),
            login_token=str(d.get("loginToken", "")),
            expires=int(d.get("expires") or 0),
            wizard_done=str(d.get("wizard")) == "1",
        )

    def _throttle_check(self) -> None:
        now = time.monotonic()
        while self._logins and now - self._logins[0] > LOGIN_WINDOW_S:
            self._logins.popleft()
        if len(self._logins) >= LOGIN_MAX_PER_WINDOW:
            wait = LOGIN_WINDOW_S - (now - self._logins[0])
            raise ThrottledError(
                f"refusing to log in again: {LOGIN_MAX_PER_WINDOW} logins in the last "
                f"{int(LOGIN_WINDOW_S)}s (retry in {int(wait)}s)"
            )
        if self._logins and now - self._logins[-1] < self._login_min_interval:
            raise ThrottledError(f"logins are less than {self._login_min_interval:g}s apart")

    async def _login(self) -> None:
        self._throttle_check()
        st = await self._status()
        self._logins.append(time.monotonic())
        self.logins_performed += 1
        r = await self._client.post(
            "login.cgi", data=login_form(self._username, self._password, st.login_token)
        )
        if r.status_code == 403:
            try:
                detail = r.json()
            except (json.JSONDecodeError, ValueError):
                detail = {}
            raise AuthError(explain_login_failure(detail), detail)
        # Success is a 302 to "/" (a browser follows it); loginStatus is the real check.
        if not (r.is_success or r.status_code == 302):
            raise AuthError(f"login.cgi -> HTTP {r.status_code}")
        st = await self._status()
        if not st.logged_in:
            raise AuthError("login returned 200 but the router reports no session")
        self._form_token = st.form_token
        log.info("logged in to %s", self.base_url)

    async def _ensure(self) -> None:
        st = await self._status()
        if st.logged_in:
            self._form_token = st.form_token
            return
        await self._login()

    # -- public, serialised ------------------------------------------------

    async def status(self) -> LoginStatus:
        async with self._lock:
            return await self._status()

    async def get_cgi(self, page: str) -> CgiData:
        return parse_cgi(await self.get_cgi_text(page))

    async def get_cgi_text(self, page: str) -> str:
        async with self._lock:
            await self._ensure()
            r = await self._client.get(f"cgi/cgi_{page}.js")
            if r.status_code in (401, 403):
                await self._login()
                r = await self._client.get(f"cgi/cgi_{page}.js")
            if r.status_code != 200:
                raise RouterError(f"cgi_{page}.js -> HTTP {r.status_code}")
            return r.text

    async def apply(
        self,
        fields: dict[str, str],
        *,
        action: str = "",
        action_params: str = "",
        to: str = "apply_abstract.cgi",
    ) -> httpx.Response:
        """Write config fields by their opaque ids (from a fresh `get_cgi`)."""
        async with self._lock:
            await self._ensure()
            form: dict[str, str] = {"token": self._form_token}
            if action:
                form["action"] = action
            if action_params:
                form["action_params"] = action_params
            form.update(fields)
            r = await self._client.post(to, data=form)
            if r.status_code >= 400:
                raise RouterError(f"{to} -> HTTP {r.status_code}")
            return r

    async def db(self, payload: dict[str, Any], *, to: str = "db.cgi") -> httpx.Response:
        """Table writes: `data=<JSON {type, to, body}>`."""
        async with self._lock:
            await self._ensure()
            form = {"data": json.dumps(payload, separators=(",", ":")), "token": self._form_token}
            r = await self._client.post(to, data=form)
            if r.status_code >= 400:
                raise RouterError(f"{to} -> HTTP {r.status_code}")
            return r

    async def post_form(self, path: str, form: dict[str, str]) -> httpx.Response:
        """Other UI endpoints (diagnostics.cgi, ...); token added automatically."""
        async with self._lock:
            await self._ensure()
            r = await self._client.post(path, data={**form, "token": self._form_token})
            if r.status_code >= 400:
                raise RouterError(f"{path} -> HTTP {r.status_code}")
            return r

    async def logout(self) -> None:
        async with self._lock:
            if self._form_token:
                await self._client.post("logout.cgi", data={"token": self._form_token})
                self._form_token = ""
