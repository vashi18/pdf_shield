from __future__ import annotations

import hashlib
import ipaddress
import re
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import fitz
from pypdf import PdfReader

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w])", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")


def validate_pdf(content: bytes, filename: str, max_bytes: int) -> tuple[bool, str]:
    if not filename.lower().endswith(".pdf"):
        return False, "Only files with a .pdf extension are accepted."
    if not content:
        return False, "The uploaded file is empty."
    if len(content) > max_bytes:
        return False, f"The file exceeds the configured {max_bytes // (1024 * 1024)} MB upload limit."
    if not content.startswith(b"%PDF-"):
        return False, "The file does not contain a valid PDF signature."
    return True, "ok"


def _finding(code: str, label: str, status: str, evidence: str, severity: str = "info") -> dict[str, Any]:
    return {"code": code, "label": label, "status": status, "evidence": evidence, "severity": severity}


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = value.rstrip(".,;:)]}")
        if cleaned and cleaned not in seen:
            result.append(cleaned)
            seen.add(cleaned)
    return result


def analyze_pdf(content: bytes, filename: str, max_bytes: int = 25 * 1024 * 1024) -> dict[str, Any]:
    valid, message = validate_pdf(content, filename, max_bytes)
    if not valid:
        raise ValueError(message)

    sha256 = hashlib.sha256(content).hexdigest()
    raw_text = content.decode("latin-1", errors="ignore")
    findings: list[dict[str, Any]] = []
    limitations: list[str] = [
        "Static parsing cannot prove that a document is benign or malicious.",
        "Extracted URLs and indicators were not contacted or executed.",
        "Reputation intelligence is separate from document-structure evidence.",
    ]
    metadata: dict[str, Any] = {}
    page_count: int | None = None
    encrypted: bool | None = None
    parsing_status = "readable"
    extracted_text = raw_text

    try:
        doc = fitz.open(stream=content, filetype="pdf")
        page_count = doc.page_count
        encrypted = bool(doc.is_encrypted)
        if encrypted:
            parsing_status = "partially_inspected"
            limitations.append("The PDF is encrypted; some objects may not be inspectable without a password.")
        metadata = {str(k).replace("/", ""): v for k, v in (doc.metadata or {}).items() if v}
        text_parts: list[str] = []
        for page in doc:
            try:
                text_parts.append(page.get_text("text"))
            except Exception:
                continue
        extracted_text = "\n".join(text_parts) + "\n" + raw_text
        doc.close()
    except Exception as exc:
        parsing_status = "parser_failed"
        limitations.append(f"Primary PDF parser failed safely: {type(exc).__name__}.")

    try:
        reader = PdfReader(BytesIO(content), strict=False)
        if page_count is None:
            page_count = len(reader.pages)
        if reader.metadata:
            metadata.update({str(k).lstrip("/"): str(v) for k, v in reader.metadata.items() if v})
        encrypted = bool(reader.is_encrypted) if encrypted is None else encrypted
    except Exception as exc:
        if parsing_status == "readable":
            parsing_status = "partially_inspected"
        limitations.append(f"Secondary parser could not inspect all objects: {type(exc).__name__}.")

    marker_counts = {
        "javascript": len(re.findall(r"/(?:JavaScript|JS)\b", raw_text, re.IGNORECASE)),
        "automatic_action": len(re.findall(r"/(?:OpenAction|AA)\b", raw_text, re.IGNORECASE)),
        "embedded_file": len(re.findall(r"/(?:EmbeddedFile|Filespec|EmbeddedFiles)\b", raw_text, re.IGNORECASE)),
        "uri_annotation": len(re.findall(r"/(?:URI|SubmitForm)\b", raw_text, re.IGNORECASE)),
        "launch_action": len(re.findall(r"/Launch\b", raw_text, re.IGNORECASE)),
    }
    findings.append(_finding("javascript", "JavaScript indicators", "detected" if marker_counts["javascript"] else "not_detected", f"Found {marker_counts['javascript']} /JavaScript or /JS marker(s) in the PDF byte stream." if marker_counts["javascript"] else "No /JavaScript or /JS marker was found in the inspected byte stream.", "high" if marker_counts["javascript"] else "info"))
    findings.append(_finding("automatic_action", "Automatic action indicators", "detected" if marker_counts["automatic_action"] else "not_detected", f"Found {marker_counts['automatic_action']} /OpenAction or /AA marker(s)." if marker_counts["automatic_action"] else "No /OpenAction or /AA marker was found.", "medium" if marker_counts["automatic_action"] else "info"))
    findings.append(_finding("embedded_file", "Embedded file indicators", "detected" if marker_counts["embedded_file"] else "not_detected", f"Found {marker_counts['embedded_file']} embedded-file marker(s)." if marker_counts["embedded_file"] else "No embedded-file marker was found.", "medium" if marker_counts["embedded_file"] else "info"))
    findings.append(_finding("uri_annotation", "External URI indicators", "detected" if marker_counts["uri_annotation"] else "not_detected", f"Found {marker_counts['uri_annotation']} URI/form marker(s); destinations were not visited." if marker_counts["uri_annotation"] else "No URI annotation marker was found.", "low" if marker_counts["uri_annotation"] else "info"))
    findings.append(_finding("launch_action", "Launch action indicators", "detected" if marker_counts["launch_action"] else "not_detected", f"Found {marker_counts['launch_action']} /Launch marker(s)." if marker_counts["launch_action"] else "No /Launch marker was found.", "high" if marker_counts["launch_action"] else "info"))
    findings.append(_finding("encryption", "Encryption status", "detected" if encrypted else "not_detected" if encrypted is False else "not_inspected", "The document reports encryption." if encrypted else "The document does not report encryption." if encrypted is False else "Encryption status could not be confirmed.", "low" if encrypted else "info"))

    urls = _unique(URL_RE.findall(extracted_text))
    domains = _unique([m.group(0).lower() for m in DOMAIN_RE.finditer(extracted_text) if "@" not in m.group(0)])
    ips: list[str] = []
    for candidate in IP_RE.findall(extracted_text):
        try:
            ipaddress.ip_address(candidate)
            ips.append(candidate)
        except ValueError:
            pass
    ips = _unique(ips)
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if host and host not in domains and not re.fullmatch(r"\d+(?:\.\d+){3}", host):
            domains.append(host)

    if urls:
        findings.append(_finding("extracted_urls", "Extracted external URLs", "detected", f"Extracted {len(urls)} URL(s); no URL was opened.", "low"))
    else:
        findings.append(_finding("extracted_urls", "Extracted external URLs", "not_detected", "No HTTP(S) URL was extracted from inspected text or objects."))

    iocs = [{"type": "url", "value": value} for value in urls]
    iocs += [{"type": "domain", "value": value} for value in domains]
    iocs += [{"type": "ip", "value": value} for value in ips]
    return {
        "filename": Path(filename).name,
        "size_bytes": len(content),
        "sha256": sha256,
        "status": "completed",
        "parsing_status": parsing_status,
        "metadata": metadata,
        "page_count": page_count,
        "encrypted": encrypted,
        "findings": findings,
        "limitations": limitations,
        "iocs": iocs,
        "marker_counts": marker_counts,
    }
