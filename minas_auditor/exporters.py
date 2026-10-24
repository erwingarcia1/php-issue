from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import AuditResult


CSV_COLUMNS = ["input_url", "final_url", "started_at", "completed_at", "check", "status", "summary", "evidence", "confidence", "error"]


def rows(results: Iterable[AuditResult]) -> list[list[str]]:
    output: list[list[str]] = [CSV_COLUMNS]
    for result in results:
        if not result.findings:
            output.append([result.input_url, result.final_url, result.started_at, result.completed_at, "audit", "error", "No findings", "", "high", result.error])
        for finding in result.findings:
            output.append([
                result.input_url, result.final_url, result.started_at, result.completed_at,
                finding.check, finding.status.value, finding.summary, finding.evidence,
                finding.confidence.value, result.error,
            ])
    return output


def export_csv(results: list[AuditResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows(rows(results))


def export_json(results: list[AuditResult], path: Path) -> None:
    path.write_text(json.dumps([result.to_dict() for result in results], indent=2), encoding="utf-8")


def export_pdf(results: list[AuditResult], path: Path) -> None:
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#183153"), alignment=TA_CENTER)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=body, fontSize=8, leading=10)
    document = SimpleDocTemplate(str(path), pagesize=letter, rightMargin=0.55 * inch, leftMargin=0.55 * inch, topMargin=0.55 * inch, bottomMargin=0.55 * inch, title="MINAS AI Website Audit")
    story = [Paragraph("MINAS AI Website Audit", title), Paragraph("Nonintrusive public-site observations with evidence and confidence labels", styles["Italic"]), Spacer(1, 16)]
    for index, result in enumerate(results):
        story.append(Paragraph(result.input_url, styles["Heading1"]))
        story.append(Paragraph(f"Final URL: {result.final_url or 'Unavailable'}<br/>Observed: {result.started_at} to {result.completed_at}", body))
        if result.error:
            story.append(Paragraph(f"Audit error: {result.error}", body))
        table_data = [["Check", "Status", "Finding", "Confidence"]]
        for finding in result.findings:
            text = finding.summary
            if finding.evidence:
                text += f"<br/><font size='7'>{escape(finding.evidence[:700])}</font>"
            table_data.append([Paragraph(escape(finding.check), small), Paragraph(finding.status.value, small), Paragraph(escape(text), small), Paragraph(finding.confidence.value, small)])
        table = Table(table_data, colWidths=[1.15 * inch, 0.7 * inch, 4.45 * inch, 0.7 * inch], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#183153")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b8c2cc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fa")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([Spacer(1, 8), table])
        if index < len(results) - 1:
            story.append(PageBreak())
    story.extend([Spacer(1, 18), Paragraph("Scope note: This report contains observational checks only. PHP patch and plugin security status remain unverified without authorized evidence. No exploit attempts, intrusive scans, or form submissions were performed.", small)])
    document.build(story)


def escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def export_google_sheet(results: list[AuditResult], spreadsheet_id: str, credentials_path: Path | None) -> None:
    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise RuntimeError("Google Sheets export requires: pip install '.[google]'") from exc
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    path = credentials_path or (Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"]) if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") else None)
    if path is None:
        raise RuntimeError("Supply --google-credentials or GOOGLE_APPLICATION_CREDENTIALS")
    credentials = Credentials.from_service_account_file(str(path), scopes=scopes)
    service = build("sheets", "v4", credentials=credentials, cache_discovery=False)
    values = rows(results)
    metadata = service.spreadsheets().get(spreadsheetId=spreadsheet_id, fields="sheets.properties.title").execute()
    titles = {sheet["properties"]["title"] for sheet in metadata.get("sheets", [])}
    if "MINAS Audit" not in titles:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"requests": [{"addSheet": {"properties": {"title": "MINAS Audit"}}}]},
        ).execute()
    else:
        service.spreadsheets().values().clear(spreadsheetId=spreadsheet_id, range="'MINAS Audit'!A:J").execute()
    service.spreadsheets().values().update(spreadsheetId=spreadsheet_id, range="MINAS Audit!A1", valueInputOption="RAW", body={"values": values}).execute()

