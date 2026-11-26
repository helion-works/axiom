"""Axiom configuration from environment variables."""

import os
import tempfile
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")


def getenv_compat(name: str, default: str = "") -> str:
    """Read AXIOM_<x>, falling back to the deprecated AGENTAV_<x> and MCPGUARD_<x> names."""
    val = os.getenv(name)
    if val is None and name.startswith("AXIOM_"):
        suffix = name[len("AXIOM_"):]
        for legacy in ("AGENTAV_", "MCPGUARD_"):
            val = os.getenv(legacy + suffix)
            if val is not None:
                break
    return default if val is None else val


def env_flag(name: str) -> bool:
    return getenv_compat(name).strip().lower() in ("1", "true", "yes")


class Settings:
    APP_NAME = os.getenv("APP_NAME", "Axiom")
    APP_ENV = os.getenv("APP_ENV", "development")
    APP_DEBUG = os.getenv("APP_DEBUG", "true").lower() == "true"
    APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT = int(os.getenv("APP_PORT", "8000"))
    # Host-touching endpoints (scan/local, discover, scan/live/*) are disabled
    # in production unless this is 1/true/yes. See host_access_allowed().
    AXIOM_ALLOW_HOST_ACCESS = env_flag("AXIOM_ALLOW_HOST_ACCESS")

    # Secret key: required in production, dev fallback otherwise
    _raw_secret = os.getenv("APP_SECRET_KEY", "")
    if APP_ENV == "production" and not _raw_secret:
        raise ValueError(
            "APP_SECRET_KEY must be set in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )
    APP_SECRET_KEY = _raw_secret or "dev-secret-key-do-not-use-in-prod"

    # CORS: comma-separated list of allowed origins for production
    CORS_ALLOWED_ORIGINS = [
        o.strip()
        for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
        if o.strip()
    ]

    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    # Claude model used by every AI feature (scan analysis and `threatmodel --ai`)
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "") or "claude-sonnet-4-20250514"
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
    OSV_API_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1")

    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
    MAX_REPO_SIZE_MB = int(os.getenv("MAX_REPO_SIZE_MB", "100"))
    TEMP_SCAN_DIR = os.getenv(
        "TEMP_SCAN_DIR",
        os.path.join(tempfile.gettempdir(), "axiom_scans"),
    )


def current_env() -> str:
    """APP_ENV read at call time (default ``development``)."""
    return os.getenv("APP_ENV", "development").strip().lower() or "development"


def host_access_allowed() -> bool:
    """True when host-touching endpoints may be served.

    Always true outside production. In production it requires
    AXIOM_ALLOW_HOST_ACCESS (or the deprecated AGENTAV_/MCPGUARD_ALLOW_HOST_ACCESS) to be
    1, true or yes (case-insensitive).
    """
    if current_env() != "production":
        return True
    return explicit_host_access()


def explicit_host_access() -> bool:
    return env_flag("AXIOM_ALLOW_HOST_ACCESS")


settings = Settings()
