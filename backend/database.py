from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[2]
raw_database_url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'pdfshield.db'}")
use_managed_db = os.getenv("PDFSHIELD_USE_MANAGED_DB", "false").lower() == "true"
if raw_database_url.startswith(("mysql://", "mysql+mysqldb://")) and use_managed_db:
    DATABASE_URL = raw_database_url.replace("mysql://", "mysql+pymysql://", 1).replace("mysql+mysqldb://", "mysql+pymysql://", 1)
else:
    DATABASE_URL = f"sqlite:///{BASE_DIR / 'pdfshield.db'}"

connect_args = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
