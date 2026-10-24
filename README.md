# MINAS AI Website Auditor

MINAS audits public business websites from a CSV and produces evidence-oriented CSV, JSON, and PDF reports. It uses Python, Playwright, Chromium, and cautious HTTP checks. The default workflow is observational: it does not exploit vulnerabilities, brute-force paths, submit forms, authenticate, or change target systems.

## What it checks

- HTTPS, redirect chains, TLS negotiation, and certificate expiry
- Up to a configured number of discovered same-origin links
- A 390px mobile viewport, horizontal overflow, viewport metadata, and tiny text signals
- Visible title, H1, language, image-alt, and low-content inconsistencies
- Passive CMS indicators in public HTML and response headers
- Optional Lighthouse performance score when the Lighthouse CLI is installed
- Signed, owner-authorized response-header review in deeper-check mode

Every finding records UTC timestamps, evidence, a result status, and a confidence level. PHP patch status and plugin security status are always marked `unverified` unless a future authorized evidence provider supplies server-side inventory. Passive CMS detection never claims a patch or plugin is secure.

## Install

Python 3.11+, Chromium, and Node.js are recommended.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev,google]'
playwright install chromium
npm install -g lighthouse
```

Google dependencies and Lighthouse are optional. Without Lighthouse, its finding is recorded as skipped. Without Google dependencies, local reports still work and Google export returns a clear error.

## Run

Prepare a CSV with a header named `url`, `website`, `website_url`, or `site`:

```csv
business_name,url
Example Business,https://example.com
```

Then run:

```sh
minas-audit examples/sites.csv --output-dir audit-output --accept-site-terms
```

Useful controls:

```sh
minas-audit sites.csv \
  --max-links 20 \
  --delay 1.0 \
  --timeout 15 \
  --retries 2 \
  --concurrency 2 \
  --accept-site-terms \
  --no-lighthouse
```

The minimum delay is 0.25 seconds, link checks are capped at 100 per site, and site concurrency is capped at 5. A `Crawl-delay` in robots.txt increases the configured delay. Rules are enforced for each discovered path and rechecked when a redirect changes origin. If robots policy cannot be read, MINAS fails closed and skips that site. `--accept-site-terms` is a required operator attestation that every listed site's terms have been reviewed and permit the audit; without it, targets are recorded as skipped. Robots permission does not replace contractual permission.

Only public HTTP(S) destinations are accepted. DNS results and browser subrequests are checked to block private, loopback, link-local, multicast, and reserved network addresses; redirects are revalidated before they are followed.

Outputs include:

- `audit-results.csv`: one normalized row per finding
- `audit-evidence.json`: full machine-readable results and metadata
- `audit-report.pdf`: a professional client-facing report
- `minas-audit.log`: timestamped operational and error log
- `<domain>-mobile.png`: mobile visual evidence
- `<domain>-lighthouse.json`: Lighthouse source evidence, when available

## Google Sheets export

Share the destination spreadsheet with a Google service account, then use credentials stored outside the repository:

```sh
minas-audit sites.csv \
  --google-sheet-id YOUR_SPREADSHEET_ID \
  --google-credentials /secure/path/service-account.json
```

The tool writes the `MINAS Audit` sheet range. It never logs credential contents. Do not commit service-account files.

## Authorization-gated checks

Deeper mode currently adds an owner-approved review of public security response headers. It remains non-exploitative. The authorization manifest binds an owner, allowed domains, expiry, and scope to an HMAC signature. Keep the signing key out of source control and provide it through `MINAS_AUTHORIZATION_KEY`.

To sign a manifest, remove `signature`, serialize it as compact JSON with sorted keys, and calculate an HMAC-SHA256 using the agreed owner authorization key. See [the example](examples/authorization.example.json). Run:

```sh
MINAS_AUTHORIZATION_KEY='provided-out-of-band' \
  minas-audit sites.csv --authorization /secure/path/authorization.json
```

Expired, altered, incorrectly scoped, or off-domain manifests are rejected and the deeper check is recorded as skipped. This gate documents technical authorization; the operator remains responsible for confirming that the signer can authorize the listed domains and that the checks comply with applicable terms and law.

## Tests

```sh
pytest -q
```

The integration test starts a local fixture, launches Chromium, enforces robots policy, detects a broken internal link, checks the mobile viewport, and verifies unverified/security-gate behavior. Export tests validate CSV, JSON, and PDF output.

## Operational guidance

Run only against sites you are permitted to assess. Start with low concurrency and increase delays for larger batches. Preserve `audit-evidence.json` and source artifacts with the report so findings remain traceable. Errors are isolated per site, retried only for transient network failures, logged with timestamps, and returned with exit code `2` if any site audit cannot complete.
