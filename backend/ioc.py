from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

HASH_RE = re.compile(r"^[a-fA-F0-9]{32,128}$")


def normalize_ioc(value: str, ioc_type: str) -> str:
    value = value.strip()
    if ioc_type == "sha256":
        return value.lower()
    if ioc_type == "domain":
        return value.rstrip(".").lower()
    if ioc_type == "ip":
        return str(ipaddress.ip_address(value))
    if ioc_type == "url":
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if not scheme or not host:
            return value.lower().rstrip("/")
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        return urlunsplit((scheme, netloc, parsed.path or "", parsed.query, ""))
    return value.lower()


def infer_ioc_type(value: str) -> str | None:
    candidate = value.strip()
    if HASH_RE.fullmatch(candidate):
        return "sha256" if len(candidate) == 64 else "hash"
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass
    if candidate.lower().startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", candidate.lower()):
        return "domain"
    return None


def build_ioc_rows(raw_iocs: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    rows: list[dict] = []
    for item in raw_iocs:
        ioc_type = item.get("type") or infer_ioc_type(item.get("value", ""))
        value = item.get("value", "").strip()
        if not ioc_type or not value:
            continue
        normalized = normalize_ioc(value, ioc_type)
        key = (ioc_type, normalized)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"type": ioc_type, "value": value, "normalized_value": normalized})
    return rows
