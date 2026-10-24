from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from playwright.async_api import Browser, async_playwright

from .checks import (
    cms_indicators,
    content_consistency,
    http_get_with_retries,
    internal_links,
    lighthouse,
    mobile_layout,
    patch_status_findings,
    redirect_and_https,
    security_headers,
    tls_certificate,
)
from .config import AuditConfig
from .models import AuditResult, Confidence, Finding, Status
from .policy import ensure_public_target, robots_decision, verify_authorization

LOGGER = logging.getLogger(__name__)


class WebsiteAuditor:
    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

    async def audit_many(self, urls: list[str]) -> list[AuditResult]:
        semaphore = asyncio.Semaphore(self.config.max_concurrency)
        async with async_playwright() as playwright:
            configured_browser = os.environ.get("MINAS_CHROMIUM_PATH")
            system_browser = configured_browser or shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
            launch_options = {"headless": True}
            if system_browser:
                launch_options["executable_path"] = system_browser
            browser = await playwright.chromium.launch(**launch_options)
            try:
                async def bounded(url: str) -> AuditResult:
                    async with semaphore:
                        return await self.audit_one(url, browser)
                return await asyncio.gather(*(bounded(url) for url in urls))
            finally:
                await browser.close()

    async def audit_one(self, input_url: str, browser: Browser) -> AuditResult:
        result = AuditResult(input_url=input_url)
        parsed = urlparse(input_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            result.error = "URL must be an absolute HTTP or HTTPS URL"
            result.findings.append(Finding("input", Status.ERROR, result.error, confidence=Confidence.HIGH))
            result.finish()
            return result
        if not self.config.terms_confirmed:
            result.findings.append(Finding("site_terms", Status.SKIPPED, "Audit skipped until the operator confirms the site's terms permit these checks", "Run with explicit terms confirmation", Confidence.HIGH))
            result.findings.extend(patch_status_findings())
            result.finish()
            return result

        headers = {"User-Agent": self.config.user_agent}
        timeout = httpx.Timeout(self.config.timeout_seconds)
        limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)
        try:
            async with httpx.AsyncClient(headers=headers, timeout=timeout, limits=limits, follow_redirects=False) as client:
                if not self.config.allow_private_hosts:
                    await ensure_public_target(input_url)
                policy = await robots_decision(client, input_url, self.config.user_agent)
                result.metadata["robots"] = {"allowed": policy.allowed, "source": policy.source, "crawl_delay": policy.crawl_delay}
                if not policy.allowed:
                    result.findings.append(Finding("robots", Status.SKIPPED, "Audit skipped because robots.txt disallows access or could not be verified", policy.source, Confidence.HIGH))
                    result.findings.extend(patch_status_findings())
                    result.finish()
                    return result
                delay = max(self.config.request_delay_seconds, policy.crawl_delay or 0)
                result.findings.append(Finding("robots", Status.PASS, "robots.txt permits this public audit", f"source={policy.source}; applied_delay={delay}s"))
                await asyncio.sleep(delay)
                response = await http_get_with_retries(client, input_url, self.config.retries)
                redirect_chain = [str(response.url)]
                for _ in range(10):
                    if not response.is_redirect or "location" not in response.headers:
                        break
                    next_url = urljoin(str(response.url), response.headers["location"])
                    if not self.config.allow_private_hosts:
                        await ensure_public_target(next_url)
                    next_policy = await robots_decision(client, next_url, self.config.user_agent)
                    if not next_policy.allowed:
                        result.findings.append(Finding("robots", Status.SKIPPED, "Redirect destination disallows the audit", next_policy.source, Confidence.HIGH))
                        result.findings.extend(patch_status_findings())
                        result.finish()
                        return result
                    policy = next_policy
                    delay = max(delay, next_policy.crawl_delay or 0)
                    await asyncio.sleep(delay)
                    response = await http_get_with_retries(client, next_url, self.config.retries)
                    redirect_chain.append(str(response.url))
                else:
                    raise RuntimeError("Redirect limit exceeded (10)")
                response.extensions["minas_redirect_chain"] = redirect_chain
                result.final_url = str(response.url)
                result.findings.extend(redirect_and_https(response))
                result.findings.append(await tls_certificate(result.final_url, self.config.timeout_seconds))

                context = await browser.new_context(
                    viewport={"width": 390, "height": 844},
                    user_agent=self.config.user_agent,
                    java_script_enabled=True,
                    service_workers="block",
                )
                page = await context.new_page()
                # Block high-bandwidth media while retaining CSS, images, and scripts needed for layout evidence.
                async def safe_route(route):
                    if route.request.resource_type in {"media", "font"}:
                        await route.abort()
                        return
                    request_url = route.request.url
                    if not self.config.allow_private_hosts and urlparse(request_url).scheme in {"http", "https"}:
                        try:
                            await ensure_public_target(request_url)
                        except ValueError:
                            LOGGER.warning("Blocked browser request to non-public target: %s", request_url)
                            await route.abort()
                            return
                    await route.continue_()
                await page.route("**/*", safe_route)
                try:
                    await page.goto(result.final_url, wait_until="domcontentloaded", timeout=int(self.config.timeout_seconds * 1000))
                    await page.wait_for_timeout(500)
                    slug = safe_slug(parsed.hostname)
                    if self.config.screenshots:
                        screenshot = self.config.output_dir / f"{slug}-mobile.png"
                        await page.screenshot(path=str(screenshot), full_page=True)
                        result.metadata["mobile_screenshot"] = str(screenshot)
                    result.findings.append(await mobile_layout(page))
                    result.findings.append(await content_consistency(page))
                    result.findings.append(await cms_indicators(page, response))
                    result.findings.append(await internal_links(page, client, result.final_url, self.config.max_internal_links, delay, self.config.retries, policy, self.config.user_agent))
                finally:
                    await context.close()

                result.findings.extend(patch_status_findings())
                authorized, authorization_evidence = verify_authorization(self.config.authorization_file, parsed.hostname)
                if authorized:
                    result.findings.append(security_headers(response, authorization_evidence))
                else:
                    result.findings.append(Finding("authorized_deeper_checks", Status.SKIPPED, "Owner-approved deeper checks were not run", authorization_evidence, Confidence.HIGH))

                if self.config.lighthouse:
                    lighthouse_path = self.config.output_dir / f"{safe_slug(parsed.hostname)}-lighthouse.json"
                    result.findings.append(await asyncio.to_thread(lighthouse, result.final_url, lighthouse_path, self.config.timeout_seconds))
        except (httpx.HTTPError, OSError, RuntimeError) as exc:
            LOGGER.exception("Audit failed for %s", input_url)
            result.error = f"{type(exc).__name__}: {exc}"
            result.findings.append(Finding("audit", Status.ERROR, "Audit could not complete", result.error, Confidence.HIGH))
            if not any(f.check == "php_patch_status" for f in result.findings):
                result.findings.extend(patch_status_findings())
        result.finish()
        return result


def safe_slug(hostname: str) -> str:
    return "".join(character if character.isalnum() or character in "-." else "-" for character in hostname)[:100]

