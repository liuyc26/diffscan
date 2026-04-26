from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class RepoCreate(BaseModel):
    name: Optional[str] = None        # derived from path/url if omitted
    path: Optional[str] = None        # local path
    remote_url: Optional[str] = None  # https:// or git@ URL
    description: str = ""
    monitor_enabled: bool = False
    monitor_interval_minutes: int = 60


class RepoUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    monitor_enabled: Optional[bool] = None
    monitor_interval_minutes: Optional[int] = None


class RepoOut(BaseModel):
    id: int
    name: str
    remote_url: Optional[str]
    path: str
    description: str
    monitor_enabled: bool
    monitor_interval_minutes: int
    last_scanned_commit: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    repo_id: int
    status: str
    commits_scanned: int
    findings_count: int
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    repo_name: Optional[str] = None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    scan_id: int
    commit_hash: str
    commit_message: str
    author: str
    file_path: str
    line_number: Optional[int]
    rule_name: str
    severity: str
    description: str
    matched_value_masked: str
    line_content_masked: str
    resolved: bool
    resolved_at: Optional[datetime]
    created_at: datetime
    repo_name: Optional[str] = None

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    total_repos: int
    total_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
