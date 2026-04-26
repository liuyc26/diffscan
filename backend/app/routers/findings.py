from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session, joinedload
from typing import Optional

from ..database import get_db
from ..models import Finding, Scan, Repository
from ..schemas import FindingOut, StatsOut

router = APIRouter(prefix="/findings", tags=["findings"])


def _enrich(f: Finding, db: Session) -> FindingOut:
    out = FindingOut.model_validate(f)
    out.repo_name = f.scan.repository.name if f.scan and f.scan.repository else None
    return out


@router.get("/", response_model=list[FindingOut])
def list_findings(
    repo_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    show_resolved: bool = Query(False),
    limit: int = Query(200, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = (
        db.query(Finding)
        .join(Scan)
        .options(joinedload(Finding.scan).joinedload(Scan.repository))
        .order_by(Finding.id.desc())
    )
    if not show_resolved:
        q = q.filter(Finding.resolved == False)
    if repo_id:
        q = q.filter(Scan.repo_id == repo_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if rule_name:
        q = q.filter(Finding.rule_name == rule_name)

    return [_enrich(f, db) for f in q.offset(offset).limit(limit).all()]


@router.patch("/{finding_id}/resolve", response_model=FindingOut)
def resolve_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.query(Finding).options(
        joinedload(Finding.scan).joinedload(Scan.repository)
    ).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.resolved = not f.resolved
    f.resolved_at = datetime.utcnow() if f.resolved else None
    db.commit()
    db.refresh(f)
    return _enrich(f, db)


@router.get("/stats", response_model=StatsOut)
def get_stats(db: Session = Depends(get_db)):
    from sqlalchemy import func
    from ..models import Repository as Repo

    total_repos = db.query(func.count(Repo.id)).scalar()
    total_scans = db.query(func.count(Scan.id)).scalar()
    # stats only count unresolved findings
    total_findings = db.query(func.count(Finding.id)).filter(Finding.resolved == False).scalar()

    sev_counts: dict[str, int] = {}
    rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.resolved == False)
        .group_by(Finding.severity)
        .all()
    )
    for sev, cnt in rows:
        sev_counts[sev] = cnt

    return StatsOut(
        total_repos=total_repos or 0,
        total_scans=total_scans or 0,
        total_findings=total_findings or 0,
        critical_findings=sev_counts.get("critical", 0),
        high_findings=sev_counts.get("high", 0),
        medium_findings=sev_counts.get("medium", 0),
        low_findings=sev_counts.get("low", 0),
    )
