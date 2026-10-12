from __future__ import annotations

import csv
import io
import json
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def analysis_payload(analysis: Any, iocs: list[Any]) -> dict:
    return {
        "id": analysis.id,
        "case_id": analysis.case_id,
        "analysis_id": analysis.id,
        "filename": analysis.filename,
        "size_bytes": analysis.size_bytes,
        "sha256": analysis.sha256,
        "status": analysis.status,
        "parsing_status": analysis.parsing_status,
        "risk_score": analysis.risk_score,
        "risk_class": analysis.risk_class,
        "risk_reasons": analysis.risk_reasons or [],
        "metadata": analysis.metadata_json or {},
        "findings": analysis.findings or [],
        "limitations": analysis.limitations or [],
        "page_count": analysis.page_count,
        "encrypted": analysis.encrypted,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "iocs": [{"id": x.id, "type": x.type, "value": x.value, "normalized_value": x.normalized_value, "source": x.source, "matched": x.matched, "match_details": x.match_details or {}} for x in iocs],
        "provenance": "PDFShield static analysis; extracted URLs were not contacted.",
    }


def json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")


def csv_bytes(rows: list[dict]) -> bytes:
    output = io.StringIO()
    fieldnames = ["type", "value", "normalized_value", "matched", "source"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows({key: row.get(key, "") for key in fieldnames} for row in rows)
    return output.getvalue().encode("utf-8")


def pdf_bytes(payload: dict) -> bytes:
    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter)
    width, height = letter
    y = height - 52
    pdf.setTitle(f"PDFShield report — {payload.get('filename', 'analysis')}")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(48, y, "PDFShield investigation report")
    y -= 28
    pdf.setFont("Helvetica", 10)
    lines = [
        f"File: {payload.get('filename')}",
        f"SHA-256: {payload.get('sha256')}",
        f"Risk: {payload.get('risk_class')} ({payload.get('risk_score')}/100)",
        f"Parsing: {payload.get('parsing_status')}",
        f"Pages: {payload.get('page_count')}",
        "",
        "Evidence and limitations:",
    ]
    lines += [f"• {reason.get('label')}: {reason.get('evidence')}" for reason in payload.get("risk_reasons", [])]
    lines += [f"• Limitation: {limitation}" for limitation in payload.get("limitations", [])]
    for line in lines:
        if y < 52:
            pdf.showPage()
            y = height - 52
            pdf.setFont("Helvetica", 10)
        pdf.drawString(48, y, line[:125])
        y -= 15
    pdf.save()
    return output.getvalue()
