"""
Axiom Package Resolver
Resolves npm and PyPI package names to GitHub repository URLs,
enabling scanning by package name instead of requiring a repo URL.

Usage:
    resolver = PackageResolver()
    info = await resolver.resolve("@modelcontextprotocol/server-filesystem")
    info = await resolver.resolve("mcp-server-sqlite")

Supports:
    - npm: @scope/package, package, package@version, npm:package
    - PyPI: package-name, package_name, package==version, pypi:package
    - Auto-detection with fallback (tries npm first, then PyPI)

The package's source repository is what gets scanned (its default branch), not the
published archive. A version in the target is kept as ``requested_version``.
"""

import re
import os
from typing import Optional, Any, Tuple
from dataclasses import dataclass, field

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore
    HAS_HTTPX = False

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"
RESOLVE_TIMEOUT = 15.0


@dataclass
class PackageInfo:
    """Resolved package metadata."""
    name: str
    ecosystem: str
    repo_url: Optional[str] = None
    version: Optional[str] = None
    description: str = ""
    homepage: Optional[str] = None
    downloads: Optional[int] = None
    author: Optional[str] = None
    license: Optional[str] = None
    deprecated: bool = False
    requested_version: Optional[str] = None   # the version written in the target, if any

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


class PackageResolver:
    """Resolves package names to repository URLs."""

    def __init__(self):
        if not HAS_HTTPX:
            raise ImportError("httpx required for package resolution. pip install httpx")

    async def resolve(self, package_name: str) -> Optional[PackageInfo]:
        """
        Resolve a package name to repo URL and metadata.
        Auto-detects ecosystem or tries both.
        """
        forced, name, requested = split_target(package_name)
        ecosystem = forced or self._detect_ecosystem(name)

        if ecosystem == "npm":
            result = await self._resolve_npm(name)
        elif ecosystem == "pypi":
            result = await self._resolve_pypi(name)
        else:
            # Try npm first (more common for MCP), then PyPI
            result = await self._resolve_npm(name)
            if not (result and result.repo_url):
                pypi_result = await self._resolve_pypi(name)
                if pypi_result and pypi_result.repo_url:
                    result = pypi_result
                else:
                    result = result or pypi_result
        if result is not None:
            result.requested_version = requested
        return result

    def _detect_ecosystem(self, name: str) -> Optional[str]:
        """Heuristic ecosystem detection."""
        if name.startswith("@"):
            return "npm"
        if "_" in name:
            return "pypi"
        return None  # try both

    async def _resolve_npm(self, name: str) -> Optional[PackageInfo]:
        """Resolve an npm package."""
        try:
            async with httpx.AsyncClient(timeout=RESOLVE_TIMEOUT) as client:
                resp = await client.get(f"{NPM_REGISTRY}/{name}")
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()

                dist_tags = data.get("dist-tags", {})
                latest = dist_tags.get("latest", "unknown")
                latest_info = data.get("versions", {}).get(latest, {})

                repo_url = self._extract_repo_url(
                    data.get("repository", {}), data.get("homepage")
                )

                downloads = await self._npm_downloads(name, client)

                author = data.get("author")
                if isinstance(author, dict):
                    author = author.get("name")
                elif not isinstance(author, str):
                    m = data.get("maintainers", [])
                    author = m[0].get("name") if m and isinstance(m[0], dict) else None

                return PackageInfo(
                    name=name, ecosystem="npm", repo_url=repo_url,
                    version=latest,
                    description=data.get("description", ""),
                    homepage=data.get("homepage"),
                    downloads=downloads, author=author,
                    license=latest_info.get("license", data.get("license")),
                    deprecated=bool(latest_info.get("deprecated")),
                )
        except Exception:
            return None

    async def _resolve_pypi(self, name: str) -> Optional[PackageInfo]:
        """Resolve a PyPI package."""
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        try:
            async with httpx.AsyncClient(timeout=RESOLVE_TIMEOUT) as client:
                resp = await client.get(f"{PYPI_API}/{normalized}/json")
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                info = resp.json().get("info", {})

                repo_url = None
                for key in ["Repository", "Source", "Source Code", "GitHub",
                            "Homepage", "Code", "Bug Tracker"]:
                    val = (info.get("project_urls") or {}).get(key, "")
                    if val and ("github.com" in val or "gitlab.com" in val):
                        repo_url = self._clean_repo_url(val)
                        break
                if not repo_url:
                    for val in [info.get("home_page"), info.get("project_url")]:
                        if val and ("github.com" in str(val) or "gitlab.com" in str(val)):
                            repo_url = self._clean_repo_url(val)
                            break

                return PackageInfo(
                    name=normalized, ecosystem="pypi", repo_url=repo_url,
                    version=info.get("version"),
                    description=info.get("summary", ""),
                    homepage=info.get("home_page"),
                    author=info.get("author") or info.get("maintainer"),
                    license=info.get("license"),
                )
        except Exception:
            return None

    def _extract_repo_url(self, repository: Any, homepage: str = None) -> Optional[str]:
        """Extract GitHub/GitLab URL from npm repository field."""
        url = None
        if isinstance(repository, dict):
            url = repository.get("url", "")
        elif isinstance(repository, str):
            url = repository
        if url:
            url = self._clean_repo_url(url)
            if url and ("github.com" in url or "gitlab.com" in url):
                return url
        if homepage and ("github.com" in homepage or "gitlab.com" in homepage):
            return self._clean_repo_url(homepage)
        return None

    def _clean_repo_url(self, url: str) -> str:
        """Normalize to https://github.com/owner/repo."""
        if not url:
            return url
        url = re.sub(r"^git\+", "", url)
        url = re.sub(r"\.git$", "", url)
        url = re.sub(r"^git://", "https://", url)
        url = re.sub(r"^ssh://git@", "https://", url)
        url = re.sub(r"^git@github\.com:", "https://github.com/", url)
        url = url.rstrip("/")
        url = re.sub(r"/(tree|blob|issues|wiki|pulls|releases)(/.*)?$", "", url)
        return url

    async def _npm_downloads(self, name: str, client) -> Optional[int]:
        try:
            r = await client.get(
                f"https://api.npmjs.org/downloads/point/last-week/{name}", timeout=5.0
            )
            return r.json().get("downloads") if r.status_code == 200 else None
        except Exception:
            return None


def split_target(target: str) -> Tuple[Optional[str], str, Optional[str]]:
    """(ecosystem forced by an ``npm:`` / ``pypi:`` prefix or None, package name, version or None)."""
    name = (target or "").strip()
    forced = None
    for prefix, eco in (("npm:", "npm"), ("pypi:", "pypi")):
        if name.lower().startswith(prefix):
            forced, name = eco, name[len(prefix):].strip()
            break
    requested = None
    if name.startswith("@") and name.count("@") > 1:      # @scope/pkg@1.2.3
        name, requested = name.rsplit("@", 1)
    elif not name.startswith("@") and "@" in name:        # pkg@1.2.3
        name, requested = name.split("@", 1)
    elif "==" in name:                                    # pkg==1.2.3
        name, requested = name.split("==", 1)
    return forced, name.strip(), ((requested or "").strip() or None)


async def resolve_package(name: str) -> Optional[PackageInfo]:
    """Convenience: resolve a package name."""
    return await PackageResolver().resolve(name)


def is_package_name(target: str) -> bool:
    """Does this look like a package name (not a URL or path)?"""
    if target.startswith(("http://", "https://", "/", "./", "../")):
        return False
    if os.path.exists(target):
        return False
    _forced, name, _requested = split_target(target)
    if name.startswith("@"):
        return bool(re.match(r'^@[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$', name))
    if "/" in name:
        return False
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9._-]*$', name))
