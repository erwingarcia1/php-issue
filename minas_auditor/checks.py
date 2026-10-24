from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from playwright.async_api import Page

from .models import Confidence, Finding, Status
from .policy import RobotsDecision

LOGGER = logging.getLogger(__name__)


async def http_get_with_retries(client: httpx.AsyncClient, url: str, retries: int) -> httpx.Response:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await client.get(url)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_error = exc
            if attempt < retries:
                await asyncio.sleep(0.5 * (2**attempt))
    assert last_error is not None
    raise last_error


def redirect_and_https(response: httpx.Response) -> list[Finding]:
    chain = response.extensions.get("minas_redirect_chain") or ([str(item.url) for item in response.history] + [str(response.url)])
    redirects = max(0, len(chain) - 1)
    final_https = response.url.scheme == "https"
    findings = [Finding(
        "redirects", Status.PASS if redirects <= 3 else Status.WARN,
        f"Observed {redirects} redirect(s)", " -> ".join(chain),
        Confidence.HIGH,
    )]
    findings.append(Finding(
        "https", Status.PASS if final_https else Status.FAIL,
        "Final page uses HTTPS" if final_https else "Final page does not use HTTPS",
        str(response.url), Confidence.HIGH,
    ))
    findings.append(Finding(
        "http_status", Status.PASS if response.status_code < 400 else Status.FAIL,
        f"Final page returned HTTP {response.status_code}", str(response.url), Confidence.HIGH,
    ))
    return findings


async def tls_certificate(url: str, timeout: float) -> Finding:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return Finding("tls", Status.SKIPPED, "TLS check skipped for non-HTTPS URL", confidence=Confidence.HIGH)
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(parsed.hostname, port, ssl=context, server_hostname=parsed.hostname), timeout
        )
        ssl_object = writer.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert() if ssl_object else {}
        protocol = ssl_object.version() if ssl_object else "unknown"
        expires_raw = certificate.get("notAfter", "")
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires_raw), timezone.utc) if expires_raw else None
        writer.close()
        await writer.wait_closed()
        days = (expires - datetime.now(timezone.utc)).days if expires else None
        status = Status.PASS if days is None or days >= 14 else Status.WARN
        return Finding("tls", status, f"TLS negotiated with {protocol}", f"certificate expires={expires}; days_remaining={days}")
    except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as exc:
        return Finding("tls", Status.FAIL, "TLS certificate validation failed", f"{type(exc).__name__}: {exc}")


async def internal_links(page: Page, client: httpx.AsyncClient, base_url: str, limit: int, delay: float, retries: int, policy: RobotsDecision, user_agent: str) -> Finding:
    hrefs: list[str] = await page.locator("a[href]").evaluate_all("els => els.map(e => e.href)")
    origin = urlparse(base_url)
    links: list[str] = []
    for href in hrefs:
        clean = urldefrag(urljoin(base_url, href))[0]
        parsed = urlparse(clean)
        if parsed.scheme in {"http", "https"} and parsed.netloc == origin.netloc and clean not in links:
            links.append(clean)
    links = links[:limit]
    broken: list[str] = []
    checked: list[str] = []
    disallowed: list[str] = []
    for link in links:
        if not policy.allows(user_agent, link):
            disallowed.append(link)
            continue
        await asyncio.sleep(delay)
        try:
            response = await http_get_with_retries(client, link, retries)
            checked.append(f"{response.status_code} {link}")
            if response.status_code >= 400:
                broken.append(f"{response.status_code} {link}")
        except httpx.HTTPError as exc:
            broken.append(f"ERROR {link} ({type(exc).__name__})")
    if not links:
        return Finding("internal_links", Status.INFO, "No eligible internal links found", confidence=Confidence.MEDIUM)
    return Finding(
        "internal_links", Status.FAIL if broken else Status.PASS,
        f"Checked {len(checked)} internal link(s); {len(broken)} broken; {len(disallowed)} excluded by robots.txt",
        "; ".join(broken if broken else checked) + (("; robots-excluded=" + ",".join(disallowed)) if disallowed else ""), Confidence.HIGH,
    )


async def mobile_layout(page: Page) -> Finding:
    result = await page.evaluate("""() => ({
      viewport: window.innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
      viewportMeta: !!document.querySelector('meta[name="viewport"]'),
      tinyText: [...document.querySelectorAll('body *')].filter(e => {
        const s = getComputedStyle(e); return e.textContent.trim() && e.children.length === 0 && parseFloat(s.fontSize) < 12;
      }).length
    })""")
    overflow = result["scrollWidth"] > result["viewport"] + 2
    good = result["viewportMeta"] and not overflow
    evidence = f"viewport={result['viewport']}px; content_width={result['scrollWidth']}px; viewport_meta={result['viewportMeta']}; tiny_text_elements={result['tinyText']}"
    return Finding("mobile_layout", Status.PASS if good else Status.WARN, "No obvious mobile overflow detected" if good else "Potential mobile layout issue detected", evidence, Confidence.MEDIUM)


async def content_consistency(page: Page) -> Finding:
    data = await page.evaluate("""() => ({
      title: document.title.trim(),
      h1: [...document.querySelectorAll('h1')].map(e => e.innerText.trim()).filter(Boolean),
      lang: document.documentElement.lang,
      bodyText: document.body.innerText.trim(),
      images: [...document.images].map(i => ({src:i.src, alt:i.getAttribute('alt')}))
    })""")
    issues: list[str] = []
    if not data["title"]: issues.append("missing page title")
    if len(data["h1"]) == 0: issues.append("missing visible H1")
    if len(data["h1"]) > 1: issues.append(f"multiple H1 elements ({len(data['h1'])})")
    if not data["lang"]: issues.append("missing document language")
    missing_alt = sum(1 for image in data["images"] if image["alt"] is None)
    if missing_alt: issues.append(f"{missing_alt} image(s) missing alt attribute")
    if len(data["bodyText"]) < 100: issues.append("very little visible text")
    return Finding(
        "visible_content", Status.WARN if issues else Status.PASS,
        "Potential visible content inconsistencies found" if issues else "Basic visible content signals are consistent",
        "; ".join(issues) or f"title={data['title']!r}; h1={data['h1'][0]!r}", Confidence.MEDIUM,
    )


async def cms_indicators(page: Page, response: httpx.Response) -> Finding:
    html = (await page.content()).lower()
    headers = " ".join(f"{key}:{value}" for key, value in response.headers.items()).lower()
    signals: list[str] = []
    patterns = {
        "WordPress": ["wp-content/", "wp-includes/", "wordpress"],
        "Drupal": ["drupal-settings-json", "/sites/default/files/", "x-generator:drupal"],
        "Joomla": ["/media/system/js/", "content=\"joomla"],
        "Shopify": ["cdn.shopify.com", "x-shopid"],
        "Wix": ["wixstatic.com", "x-wix-"],
        "Squarespace": ["static1.squarespace.com", "squarespace"],
    }
    combined = html + " " + headers
    for cms, markers in patterns.items():
        if any(marker in combined for marker in markers):
            signals.append(cms)
    return Finding(
        "cms_indicators", Status.INFO,
        f"CMS indicator(s): {', '.join(signals)}" if signals else "No common CMS indicators observed",
        "Passive HTML and response-header fingerprinting only", Confidence.MEDIUM if signals else Confidence.LOW,
    )


def patch_status_findings() -> list[Finding]:
    return [
        Finding("php_patch_status", Status.UNVERIFIED, "PHP patch status is unverified", "Requires authorized server-side package/version evidence", Confidence.UNVERIFIED),
        Finding("plugin_security_status", Status.UNVERIFIED, "Plugin security status is unverified", "Requires authorized inventory and version evidence", Confidence.UNVERIFIED),
    ]


def security_headers(response: httpx.Response, authorization_evidence: str) -> Finding:
    desired = ["strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy"]
    missing = [name for name in desired if name not in response.headers]
    return Finding(
        "authorized_security_headers", Status.WARN if missing else Status.PASS,
        f"{len(missing)} recommended response header(s) absent" if missing else "Recommended response headers observed",
        f"authorization={authorization_evidence}; missing={','.join(missing) or 'none'}", Confidence.HIGH,
    )


def lighthouse(url: str, output_path: Path, timeout: float) -> Finding:
    local_executable = Path.cwd() / "node_modules" / ".bin" / "lighthouse"
    executable = shutil.which("lighthouse") or (str(local_executable) if local_executable.is_file() else None)
    if executable is None:
        return Finding("lighthouse", Status.SKIPPED, "Lighthouse CLI is not installed", "Install with: npm install -g lighthouse", Confidence.HIGH)
    command = [executable, url, "--quiet", "--chrome-flags=--headless --no-sandbox", "--only-categories=performance", "--output=json", f"--output-path={output_path}"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=max(30, timeout * 4))
        report = json.loads(output_path.read_text(encoding="utf-8"))
        score = round(float(report["categories"]["performance"]["score"]) * 100)
        return Finding("lighthouse", Status.PASS if score >= 75 else Status.WARN, f"Lighthouse performance score: {score}/100", str(output_path), Confidence.HIGH)
    except (subprocess.SubprocessError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return Finding("lighthouse", Status.ERROR, "Lighthouse could not complete", f"{type(exc).__name__}: {exc}", Confidence.HIGH)
