from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base, utcnow


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[Optional[str]] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    parsing_status: Mapped[str] = mapped_column(String(32), default="readable")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_class: Mapped[str] = mapped_column(String(24), default="Informational")
    risk_reasons: Mapped[list] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    page_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    encrypted: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    case: Mapped[Optional["Case"]] = relationship(back_populates="analyses")
    iocs: Mapped[list["IOC"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class IOC(Base):
    __tablename__ = "iocs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[Optional[str]] = mapped_column(ForeignKey("analyses.id"), nullable=True, index=True)
    value: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[str] = mapped_column(Text, index=True)
    type: Mapped[str] = mapped_column(String(24), index=True)
    source: Mapped[str] = mapped_column(String(64), default="pdf-static-analysis")
    matched: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    match_details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    analysis: Mapped[Optional[Analysis]] = relationship(back_populates="iocs")
    __table_args__ = (Index("ix_iocs_type_normalized", "type", "normalized_value"),)


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    provider: Mapped[str] = mapped_column(String(64))
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    indicators: Mapped[list["ThreatIndicator"]] = relationship(back_populates="feed", cascade="all, delete-orphan")
    syncs: Mapped[list["FeedSync"]] = relationship(back_populates="feed", cascade="all, delete-orphan")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    feed_id: Mapped[str] = mapped_column(ForeignKey("threat_feeds.id"), index=True)
    type: Mapped[str] = mapped_column(String(24), index=True)
    value: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[str] = mapped_column(Text, index=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    feed: Mapped[ThreatFeed] = relationship(back_populates="indicators")
    __table_args__ = (UniqueConstraint("feed_id", "type", "normalized_value", name="uq_feed_indicator"),)


class FeedSync(Base):
    __tablename__ = "feed_syncs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    feed_id: Mapped[str] = mapped_column(ForeignKey("threat_feeds.id"), index=True)
    status: Mapped[str] = mapped_column(String(24))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    feed: Mapped[ThreatFeed] = relationship(back_populates="syncs")


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(24), default="New", index=True)
    analyst_notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    analyses: Mapped[list[Analysis]] = relationship(back_populates="case")
    notes: Mapped[list["AnalystNote"]] = relationship(back_populates="case", cascade="all, delete-orphan")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="notes")


class OSINTLookup(Base):
    __tablename__ = "osint_lookups"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    indicator: Mapped[str] = mapped_column(Text, index=True)
    indicator_type: Mapped[str] = mapped_column(String(24))
    provider: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    findings: Mapped[list] = mapped_column(JSON, default=list)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
