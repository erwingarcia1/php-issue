from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import sys
from pathlib import Path

from .auditor import WebsiteAuditor
from .config import AuditConfig
from .exporters import export_csv, export_google_sheet, export_json, export_pdf


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="MINAS AI Website Auditor: cautious, evidence-first public website checks")
    value.add_argument("input_csv", type=Path, help="CSV containing a url or website column")
    value.add_argument("--output-dir", type=Path, default=Path("audit-output"))
    value.add_argument("--url-column", default=None, help="Column containing URLs (auto-detected by default)")
    value.add_argument("--max-links", type=int, default=20)
    value.add_argument("--delay", type=float, default=1.0, help="Minimum seconds between requests to a site")
    value.add_argument("--timeout", type=float, default=15.0)
    value.add_argument("--retries", type=int, default=2)
    value.add_argument("--concurrency", type=int, default=2, help="Concurrent sites, maximum 5")
    value.add_argument("--no-lighthouse", action="store_true")
    value.add_argument("--no-screenshots", action="store_true")
    value.add_argument("--authorization", type=Path, help="HMAC-signed owner authorization manifest")
    value.add_argument("--accept-site-terms", action="store_true", help="Confirm you reviewed and may audit every listed site's terms")
    value.add_argument("--google-sheet-id")
    value.add_argument("--google-credentials", type=Path)
    value.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    value.add_argument("--log-file", type=Path, help="Log path (default: OUTPUT_DIR/minas-audit.log)")
    return value


def read_urls(path: Path, requested_column: str | None) -> list[str]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Input CSV has no header row")
        candidates = [requested_column] if requested_column else ["url", "website", "website_url", "site"]
        column = next((name for name in candidates if name and name in reader.fieldnames), None)
        if column is None:
            raise ValueError(f"Could not find URL column; available columns: {', '.join(reader.fieldnames)}")
        urls = [row[column].strip() for row in reader if row.get(column, "").strip()]
    if not urls:
        raise ValueError("Input CSV contains no URLs")
    return list(dict.fromkeys(urls))


async def run(arguments: argparse.Namespace) -> int:
    urls = read_urls(arguments.input_csv, arguments.url_column)
    config = AuditConfig(
        output_dir=arguments.output_dir,
        max_internal_links=arguments.max_links,
        request_delay_seconds=arguments.delay,
        timeout_seconds=arguments.timeout,
        retries=arguments.retries,
        lighthouse=not arguments.no_lighthouse,
        screenshots=not arguments.no_screenshots,
        max_concurrency=arguments.concurrency,
        authorization_file=arguments.authorization,
        terms_confirmed=arguments.accept_site_terms,
    )
    results = await WebsiteAuditor(config).audit_many(urls)
    export_csv(results, config.output_dir / "audit-results.csv")
    export_json(results, config.output_dir / "audit-evidence.json")
    export_pdf(results, config.output_dir / "audit-report.pdf")
    if arguments.google_sheet_id:
        export_google_sheet(results, arguments.google_sheet_id, arguments.google_credentials)
    errors = sum(bool(result.error) for result in results)
    logging.getLogger(__name__).info("Audited %d site(s); %d audit error(s); output=%s", len(results), errors, config.output_dir)
    return 2 if errors else 0


def main() -> None:
    arguments = parser().parse_args()
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    log_path = arguments.log_file or arguments.output_dir / "minas-audit.log"
    logging.basicConfig(
        level=getattr(logging, arguments.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(log_path, encoding="utf-8")],
    )
    try:
        raise SystemExit(asyncio.run(run(arguments)))
    except (OSError, ValueError, RuntimeError) as exc:
        logging.getLogger(__name__).error("%s", exc, exc_info=logging.getLogger().isEnabledFor(logging.DEBUG))
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
