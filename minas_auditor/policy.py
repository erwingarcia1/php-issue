from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx


async def ensure_public_target(url: str) -> None:
    """Reject loopback, private, link-local, multicast, and reserved targets."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are allowed")
    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"Hostname could not be resolved: {parsed.hostname}") from exc
    if not addresses:
        raise ValueError(f"Hostname has no addresses: {parsed.hostname}")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError(f"Non-public target address is prohibited: {parsed.hostname} ({ip})")


@dataclass(frozen=True, slots=True)
class RobotsDecision:
    allowed: bool
    source: str
    crawl_delay: float | None = None
    parser: RobotFileParser | None = None

    def allows(self, user_agent: str, url: str) -> bool:
        return self.allowed and (self.parser is None or self.parser.can_fetch(user_agent, url))


async def robots_decision(client: httpx.AsyncClient, url: str, user_agent: str) -> RobotsDecision:
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        response = await client.get(robots_url)
        if response.status_code == 404:
            return RobotsDecision(True, "robots.txt not found (HTTP 404)")
        response.raise_for_status()
        parser = RobotFileParser(robots_url)
        parser.parse(response.text.splitlines())
        delay = parser.crawl_delay(user_agent) or parser.crawl_delay("*")
        return RobotsDecision(parser.can_fetch(user_agent, url), robots_url, delay, parser)
    except (httpx.HTTPError, UnicodeError) as exc:
        # Fail closed when policy cannot be established.
        return RobotsDecision(False, f"robots.txt unavailable: {type(exc).__name__}")


def verify_authorization(path: Path | None, hostname: str) -> tuple[bool, str]:
    """Verify an HMAC-signed owner authorization manifest.

    Signing key is intentionally supplied out-of-band via MINAS_AUTHORIZATION_KEY.
    The canonical signature covers owner, domains, expires_at, and scope.
    """
    if path is None:
        return False, "No authorization manifest supplied"
    key = os.environ.get("MINAS_AUTHORIZATION_KEY")
    if not key:
        return False, "MINAS_AUTHORIZATION_KEY is not set"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        signature = document.pop("signature")
        expires = datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
        domains = [str(value).lower().rstrip(".") for value in document["domains"]]
        scope = document["scope"]
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return False, f"Invalid authorization manifest: {exc}"
    if expires <= datetime.now(timezone.utc):
        return False, "Authorization manifest has expired"
    hostname = hostname.lower().rstrip(".")
    if not any(hostname == domain or hostname.endswith("." + domain) for domain in domains):
        return False, "Hostname is outside the authorized domains"
    if "owner_approved_security_headers" not in scope:
        return False, "Required deeper-check scope is absent"
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False, "Authorization signature is invalid"
    return True, f"Authorized by {document.get('owner', 'site owner')} until {expires.isoformat()}"

