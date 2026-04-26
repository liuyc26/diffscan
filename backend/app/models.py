from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, func
)
from sqlalchemy.orm import relationship
from .database import Base


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    remote_url = Column(Text, nullable=True)   # set for remote repos
    path = Column(Text, nullable=False)        # local path (managed clone for remote repos)
    description = Column(Text, default="")
    monitor_enabled = Column(Boolean, default=False)
    monitor_interval_minutes = Column(Integer, default=60)
    last_scanned_commit = Column(String(40), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    status = Column(String(20), default="pending")  # pending | running | completed | failed
    commits_scanned = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())

    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    commit_hash = Column(String(40), nullable=False)
    commit_message = Column(Text, default="")
    author = Column(String(255), default="")
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=True)
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # critical | high | medium | low
    description = Column(Text, default="")
    matched_value_masked = Column(Text, default="")
    line_content_masked = Column(Text, default="")
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())

    scan = relationship("Scan", back_populates="findings")
