from pathlib import Path

from minas_auditor.exporters import export_csv, export_json, export_pdf
from minas_auditor.models import AuditResult, Finding, Status


def test_all_local_exports_are_created(tmp_path: Path):
    result = AuditResult(input_url="https://example.com", final_url="https://example.com")
    result.findings.append(Finding("https", Status.PASS, "Final page uses HTTPS", "https://example.com"))
    result.finish()

    export_csv([result], tmp_path / "report.csv")
    export_json([result], tmp_path / "evidence.json")
    export_pdf([result], tmp_path / "report.pdf")

    assert "Final page uses HTTPS" in (tmp_path / "report.csv").read_text()
    assert '"confidence": "high"' in (tmp_path / "evidence.json").read_text()
    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF")

