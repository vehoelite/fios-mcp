"""Where the router, its password, the pinned certificate and the policy live.

Environment variables win over `~/.config/fios-mcp/config.toml`:

    FIOS_ROUTER_URL            default https://192.168.1.1
    FIOS_ROUTER_PASSWORD_FILE  file holding the admin password (preferred)
    FIOS_ROUTER_PASSWORD       the password itself
    FIOS_ROUTER_PIN            pinned certificate, default ~/.config/fios-mcp/router.pem
    FIOS_MCP_POLICY            policy file, default ~/.config/fios-mcp/policy.toml
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "fios-mcp"


class ConfigError(RuntimeError):
    pass


def _private(path: Path) -> Path:
    if path.stat().st_mode & 0o077:
        raise ConfigError(f"{path} is readable by other users; run: chmod 600 {path}")
    return path


@dataclass
class Config:
    url: str
    password: str
    pin_file: Path
    policy_file: Path

    def __repr__(self) -> str:
        return f"Config(url={self.url!r}, password=***, pin_file={self.pin_file}, policy_file={self.policy_file})"

    @classmethod
    def load(cls) -> Config:
        file_cfg: dict = {}
        cfg_path = CONFIG_DIR / "config.toml"
        if cfg_path.exists():
            file_cfg = tomllib.loads(_private(cfg_path).read_text())

        def get(env: str, key: str, default: str | None = None) -> str | None:
            return os.environ.get(env) or file_cfg.get(key) or default

        url = get("FIOS_ROUTER_URL", "url", "https://192.168.1.1")
        password = os.environ.get("FIOS_ROUTER_PASSWORD") or file_cfg.get("password")
        pw_file = get("FIOS_ROUTER_PASSWORD_FILE", "password_file")
        if not password and pw_file:
            password = _private(Path(pw_file).expanduser()).read_text().strip()
        if not password:
            raise ConfigError("no router password: set FIOS_ROUTER_PASSWORD_FILE (preferred) or "
                              "FIOS_ROUTER_PASSWORD, or password_file in config.toml")
        pin = Path(get("FIOS_ROUTER_PIN", "pin_file", str(CONFIG_DIR / "router.pem"))).expanduser()
        policy = Path(get("FIOS_MCP_POLICY", "policy_file", str(CONFIG_DIR / "policy.toml"))).expanduser()
        return cls(url=str(url), password=password, pin_file=pin, policy_file=policy)
