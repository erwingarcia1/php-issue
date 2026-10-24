from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from minas_auditor.auditor import WebsiteAuditor
from minas_auditor.config import AuditConfig


class SiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nAllow: /\nCrawl-delay: 0\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/broken":
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b'''<!doctype html><html lang="en"><head><title>MINAS test</title><meta name="viewport" content="width=device-width"></head><body><h1>Audit fixture</h1><p>This fixture has enough visible text to exercise the content consistency check without generating a low-content warning during the integration test.</p><a href="/ok">Working</a><a href="/broken">Broken</a></body></html>'''
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def local_site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join()


@pytest.mark.asyncio
async def test_nonintrusive_audit_pipeline(local_site, tmp_path):
    config = AuditConfig(output_dir=tmp_path, max_internal_links=5, request_delay_seconds=0.25, lighthouse=False, terms_confirmed=True, allow_private_hosts=True)
    result = (await WebsiteAuditor(config).audit_many([local_site]))[0]
    findings = {finding.check: finding for finding in result.findings}

    assert result.error == ""
    assert findings["robots"].status == "pass"
    assert findings["https"].status == "fail"
    assert findings["mobile_layout"].status == "pass"
    assert findings["internal_links"].status == "fail"
    assert findings["php_patch_status"].status == "unverified"
    assert findings["plugin_security_status"].status == "unverified"
    assert findings["authorized_deeper_checks"].status == "skipped"


@pytest.mark.asyncio
async def test_terms_attestation_is_required(local_site, tmp_path):
    result = (await WebsiteAuditor(AuditConfig(output_dir=tmp_path, lighthouse=False)).audit_many([local_site]))[0]
    findings = {finding.check: finding for finding in result.findings}
    assert findings["site_terms"].status == "skipped"
    assert "robots" not in findings

