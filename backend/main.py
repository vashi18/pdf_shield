from __future__ import annotations

import csv
import io
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from .database import Base, engine, get_db, utcnow
from .models import Analysis, AnalystNote, Case, FeedSync, IOC, OSINTLookup, Setting, ThreatFeed, ThreatIndicator
from .schemas import AnalysisOut, CasePatch, OSINTRequest, SettingUpdate
from .feeds import TRUSTED_FEEDS, empty_sync, is_trusted_feed_url
from .ioc import build_ioc_rows, normalize_ioc
from .pdf_analyzer import analyze_pdf
from .reports import analysis_payload, csv_bytes, json_bytes, pdf_bytes
from .risk import score_analysis


BASE_DIR = Path(__file__).resolve().parents[1]

DIST_DIR = BASE_DIR / "frontend" / "dist"
DEFAULT_MAX_MB = int(os.getenv("PDFSHIELD_MAX_UPLOAD_MB", "25"))

app = FastAPI(title="PDFShield API", version="0.1.0", description="Defensive static PDF analysis and threat-intelligence workspace.")
origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "PATCH"], allow_headers=["*"])

if DIST_DIR.exists() and (DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=DIST_DIR / "assets"), name="assets")


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    with next(get_db()) as db:
        for feed in TRUSTED_FEEDS:
            if not db.get(ThreatFeed, feed["id"]):
                db.add(ThreatFeed(id=feed["id"], name=feed["name"], provider=feed["provider"], url=feed["url"], enabled=False, indicator_count=0))
        defaults = {
            "max_upload_mb": DEFAULT_MAX_MB,
            "external_lookup_consent": False,
            "demo_mode": False,
            "theme": "dark",
            "enabled_providers": [],
            "sync_interval_minutes": 60,
        }
        existing = {row.key for row in db.scalars(select(Setting)).all()}
        for key, value in defaults.items():
            if key not in existing:
                db.add(Setting(key=key, value={"value": value}))
        db.commit()


def setting_value(db: Session, key: str, fallback: Any) -> Any:
    setting = db.get(Setting, key)
    return setting.value.get("value", fallback) if setting and isinstance(setting.value, dict) else fallback


def as_analysis_dict(analysis: Analysis) -> dict:
    return analysis_payload(analysis, list(analysis.iocs))


def get_analysis_or_404(db: Session, analysis_id: str) -> Analysis:
    analysis = db.execute(select(Analysis).options(joinedload(Analysis.iocs)).where(Analysis.id == analysis_id)).unique().scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "pdfshield", "timestamp": utcnow().isoformat()}


@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count(Analysis.id))) or 0
    suspicious = db.scalar(select(func.count(Analysis.id)).where(Analysis.risk_score >= 30)) or 0
    iocs = db.scalar(select(func.count(IOC.id))) or 0
    matches = db.scalar(select(func.count(IOC.id)).where(IOC.matched.is_(True))) or 0
    feeds = db.scalars(select(ThreatFeed)).all()
    return {"total_pdfs": total, "suspicious_documents": suspicious, "extracted_iocs": iocs, "threat_matches": matches, "feed_health": {"configured": len(feeds), "operational": sum(1 for feed in feeds if feed.last_success_at)}}


@app.get("/api/dashboard/activity")
def dashboard_activity(db: Session = Depends(get_db)) -> dict:
    rows = db.scalars(select(Analysis).order_by(Analysis.created_at.desc()).limit(8)).all()
    by_day: dict[str, int] = {}
    for row in rows:
        day = row.created_at.astimezone().strftime("%a") if row.created_at else "—"
        by_day[day] = by_day.get(day, 0) + 1
    return {"activity": [{"label": key, "count": value} for key, value in reversed(list(by_day.items()))], "risk_distribution": [{"label": label, "count": db.scalar(select(func.count(Analysis.id)).where(Analysis.risk_class == label)) or 0} for label in ["Informational", "Low", "Medium", "High", "Critical"]]}


@app.post("/api/analyses", response_model=AnalysisOut, status_code=201)
async def create_analysis(file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict:
    filename = Path(file.filename or "upload.pdf").name
    max_mb = int(setting_value(db, "max_upload_mb", DEFAULT_MAX_MB))
    content = await file.read((max_mb * 1024 * 1024) + 1)
    try:
        result = analyze_pdf(content, filename, max_bytes=max_mb * 1024 * 1024)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"The file could not be safely inspected ({type(exc).__name__}).") from exc

    risk = score_analysis(result)
    analysis_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    case = Case(id=case_id, case_number=f"PS-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{analysis_id[:6].upper()}", title=filename, status="New")
    analysis = Analysis(id=analysis_id, case_id=case_id, filename=result["filename"], size_bytes=result["size_bytes"], sha256=result["sha256"], status=result["status"], parsing_status=result["parsing_status"], risk_score=risk["risk_score"], risk_class=risk["risk_class"], risk_reasons=risk["risk_reasons"], metadata_json=result["metadata"], findings=result["findings"], limitations=result["limitations"], page_count=result["page_count"], encrypted=result["encrypted"])
    db.add(case)
    db.add(analysis)
    threat_by_key = {(item.type, item.normalized_value): item for item in db.scalars(select(ThreatIndicator)).all()}
    for row in build_ioc_rows(result["iocs"]):
        match = threat_by_key.get((row["type"], row["normalized_value"]))
        db.add(IOC(id=str(uuid.uuid4()), analysis_id=analysis_id, value=row["value"], normalized_value=row["normalized_value"], type=row["type"], matched=bool(match), match_details={"source": match.feed.provider if match and match.feed else None, "tags": match.tags if match else [], "confidence": match.confidence if match else None} if match else {}))
    db.commit()
    return as_analysis_dict(get_analysis_or_404(db, analysis_id))


@app.get("/api/analyses")
def list_analyses(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(Analysis).options(joinedload(Analysis.iocs)).order_by(Analysis.created_at.desc()).limit(limit)).unique().scalars().all()
    return [as_analysis_dict(row) for row in rows]


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    return as_analysis_dict(get_analysis_or_404(db, analysis_id))


@app.get("/api/analyses/{analysis_id}/report")
def get_report(analysis_id: str, format: str = Query("json", pattern="^(json|pdf|csv)$"), db: Session = Depends(get_db)) -> Response:
    payload = as_analysis_dict(get_analysis_or_404(db, analysis_id))
    safe_name = Path(payload["filename"]).stem[:70]
    if format == "pdf":
        return Response(pdf_bytes(payload), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{safe_name}-pdfshield-report.pdf"'})
    if format == "csv":
        return Response(csv_bytes(payload["iocs"]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{safe_name}-iocs.csv"'})
    return Response(json_bytes(payload), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{safe_name}-report.json"'})


@app.get("/api/iocs")
def list_iocs(search: str = "", ioc_type: str = Query("", alias="type"), matched: str = "", page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict:
    query = select(IOC).order_by(IOC.created_at.desc())
    if search:
        query = query.where(IOC.value.ilike(f"%{search}%"))
    if ioc_type:
        query = query.where(IOC.type == ioc_type)
    if matched in {"true", "false"}:
        query = query.where(IOC.matched.is_(matched == "true"))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [{"id": row.id, "type": row.type, "value": row.value, "normalized_value": row.normalized_value, "source": row.source, "matched": row.matched, "match_details": row.match_details or {}} for row in rows], "total": total, "page": page, "page_size": page_size}


@app.get("/api/iocs/{ioc_id}")
def get_ioc(ioc_id: str, db: Session = Depends(get_db)) -> dict:
    row = db.get(IOC, ioc_id)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")
    return {"id": row.id, "type": row.type, "value": row.value, "normalized_value": row.normalized_value, "source": row.source, "matched": row.matched, "match_details": row.match_details or {}, "analysis_id": row.analysis_id, "created_at": row.created_at}


@app.post("/api/osint/lookup")
def lookup_osint(payload: OSINTRequest, db: Session = Depends(get_db)) -> dict:
    if not payload.consent or not setting_value(db, "external_lookup_consent", False):
        raise HTTPException(status_code=400, detail="External lookups require explicit consent in the request and Settings.")
    providers = payload.providers or setting_value(db, "enabled_providers", [])
    if not providers:
        result = {"status": "not_configured", "findings": [], "message": "No OSINT provider is enabled; no external request was made."}
    else:
        result = {"status": "unavailable", "findings": [], "message": "Configured providers are not reachable from this workspace yet; no fabricated result is shown."}
    row = OSINTLookup(id=str(uuid.uuid4()), indicator=payload.indicator, indicator_type=payload.indicator_type, provider=", ".join(providers) or "none", status=result["status"], findings=result["findings"])
    db.add(row)
    db.commit()
    return {"id": row.id, "indicator": row.indicator, "indicator_type": row.indicator_type, "provider": row.provider, **result, "created_at": row.created_at}


@app.get("/api/osint/investigations")
def list_osint(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(OSINTLookup).order_by(OSINTLookup.created_at.desc()).limit(100)).all()
    return [{"id": row.id, "indicator": row.indicator, "indicator_type": row.indicator_type, "provider": row.provider, "status": row.status, "findings": row.findings or [], "created_at": row.created_at} for row in rows]


@app.get("/api/feeds")
def list_feeds(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(ThreatFeed).order_by(ThreatFeed.name)).all()
    return [{"id": row.id, "name": row.name, "provider": row.provider, "url": row.url, "enabled": row.enabled, "last_success_at": row.last_success_at, "last_error": row.last_error, "indicator_count": row.indicator_count, "documentation": next((x["documentation"] for x in TRUSTED_FEEDS if x["id"] == row.id), None)} for row in rows]


@app.post("/api/feeds/{feed_id}/sync")
def sync_feed(feed_id: str, db: Session = Depends(get_db)) -> dict:
    feed = db.get(ThreatFeed, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Threat feed not found")
    if not feed.enabled:
        return empty_sync(feed_id, "disabled", "Feed is disabled. Enable it in Settings before synchronizing.")
    if not feed.url or not is_trusted_feed_url(feed.url):
        return empty_sync(feed_id, "blocked", "Feed URL is not in the trusted allowlist.")
    started = utcnow()
    sync = FeedSync(id=str(uuid.uuid4()), feed_id=feed_id, status="running", started_at=started, finished_at=started)
    db.add(sync)
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            response = client.get(feed.url)
            response.raise_for_status()
        candidates: list[tuple[str, str]] = []
        for line in response.text.splitlines():
            if line.startswith("#"):
                continue
            fields = next(csv.reader([line]), [])
            for field in fields:
                if field.startswith(("http://", "https://")):
                    candidates.append(("url", field.strip('"')))
                    break
        added = 0
        existing = {(row.type, row.normalized_value) for row in db.scalars(select(ThreatIndicator).where(ThreatIndicator.feed_id == feed_id)).all()}
        for ioc_type, value in candidates[:5000]:
            normalized = normalize_ioc(value, ioc_type)
            if (ioc_type, normalized) in existing:
                continue
            db.add(ThreatIndicator(id=str(uuid.uuid4()), feed_id=feed_id, type=ioc_type, value=value, normalized_value=normalized, tags=["urlhaus"]))
            existing.add((ioc_type, normalized))
            added += 1
        feed.last_success_at = utcnow()
        feed.last_error = None
        feed.indicator_count = len(existing)
        sync.status = "success"
        sync.indicator_count = added
    except Exception as exc:
        feed.last_error = f"{type(exc).__name__}: synchronization failed safely"
        sync.status = "error"
        sync.error = feed.last_error
    sync.finished_at = utcnow()
    db.commit()
    return {"feed_id": feed_id, "status": sync.status, "indicator_count": sync.indicator_count, "error": sync.error, "timestamp": sync.finished_at}


@app.get("/api/feeds/{feed_id}/history")
def feed_history(feed_id: str, db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(FeedSync).where(FeedSync.feed_id == feed_id).order_by(FeedSync.started_at.desc()).limit(30)).all()
    return [{"id": row.id, "status": row.status, "started_at": row.started_at, "finished_at": row.finished_at, "indicator_count": row.indicator_count, "error": row.error} for row in rows]


@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(select(Case).options(joinedload(Case.analyses)).order_by(Case.created_at.desc())).unique().scalars().all()
    return [{"id": row.id, "case_number": row.case_number, "title": row.title, "status": row.status, "analyses": [{"id": a.id, "filename": a.filename, "risk_score": a.risk_score, "risk_class": a.risk_class, "created_at": a.created_at} for a in row.analyses], "analyst_notes": row.analyst_notes, "created_at": row.created_at, "updated_at": row.updated_at} for row in rows]


@app.get("/api/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)) -> dict:
    row = db.execute(select(Case).options(joinedload(Case.analyses), joinedload(Case.notes)).where(Case.id == case_id)).unique().scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"id": row.id, "case_number": row.case_number, "title": row.title, "status": row.status, "analyst_notes": row.analyst_notes, "analyses": [{"id": a.id, "filename": a.filename, "risk_score": a.risk_score, "risk_class": a.risk_class, "created_at": a.created_at} for a in row.analyses], "notes": [{"id": n.id, "body": n.body, "created_at": n.created_at} for n in row.notes]}


@app.patch("/api/cases/{case_id}")
def patch_case(case_id: str, patch: CasePatch, db: Session = Depends(get_db)) -> dict:
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    if patch.status:
        row.status = patch.status
    if patch.analyst_notes is not None:
        row.analyst_notes = patch.analyst_notes
        db.add(AnalystNote(id=str(uuid.uuid4()), case_id=case_id, body=patch.analyst_notes))
    row.updated_at = utcnow()
    db.commit()
    return {"id": row.id, "status": row.status, "analyst_notes": row.analyst_notes, "updated_at": row.updated_at}


@app.get("/api/settings")
def get_settings(db: Session = Depends(get_db)) -> dict:
    return {row.key: row.value.get("value") for row in db.scalars(select(Setting)).all()}


@app.patch("/api/settings")
def update_settings(payload: SettingUpdate, db: Session = Depends(get_db)) -> dict:
    updates = payload.model_dump(exclude_none=True)
    for key, value in updates.items():
        row = db.get(Setting, key)
        if not row:
            row = Setting(key=key, value={"value": value})
            db.add(row)
        else:
            row.value = {"value": value}
            row.updated_at = utcnow()
    db.commit()
    return get_settings(db)


@app.get("/{path:path}")
def spa_fallback(path: str):
    if path in {"", "index.html"} or not path:
        index = DIST_DIR / "index.html"
    else:
        candidate = DIST_DIR / path
        index = candidate if candidate.is_file() else DIST_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return JSONResponse({"detail": "Frontend build not found. Run the frontend build first."}, status_code=503)
