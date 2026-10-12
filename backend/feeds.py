from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

TRUSTED_FEEDS = [
    {
        "id": "urlhaus-community",
        "name": "URLhaus Community Feed",
        "provider": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "documentation": "https://urlhaus.abuse.ch/api/",
        "enabled": False,
    }
]


def is_trusted_feed_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in {"urlhaus.abuse.ch"}


def empty_sync(feed_id: str, status: str, error: str | None = None) -> dict:
    return {
        "feed_id": feed_id,
        "status": status,
        "indicator_count": 0,
        "error": error,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
