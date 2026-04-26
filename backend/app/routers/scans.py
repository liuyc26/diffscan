import os
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
import git

from ..database import get_db, SessionLocal
from ..models import Repository, Scan, Finding
from ..schemas import ScanOut, FindingOut
from ..scanner import scan_repository, mask_value, mask_line

router = APIRouter(prefix="/scans", tags=["scans"])


def _prepare_repo(remote_url: str, local_path: str) -> None:
    """Clone if not present, pull if already cloned."""
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    if os.path.isdir(os.path.join(local_path, ".git")):
        r = git.Repo(local_path)
        r.remotes.origin.pull()
    else:
        os.makedirs(local_path, exist_ok=True)
        git.Repo.clone_from(remote_url, local_path)


def run_scan(scan_id: int, repo_path: str, since_commit: str | None, remote_url: str | None = None, depth: str = "latest", branch: str = ""):
    """Background task: run the scanner and persist results."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        if remote_url:
            _prepare_repo(remote_url, repo_path)

        raw_findings, scanned_shas, head_sha = scan_repository(repo_path, since_commit, depth, branch)

        for rf in raw_findings:
            masked_val = mask_value(rf.matched_value)
            masked_line = mask_line(rf.line_content.strip()[:500], rf.matched_value)
            finding = Finding(
                scan_id=scan_id,
                commit_hash=rf.__dict__.get("commit_hash", ""),
                commit_message=rf.__dict__.get("commit_message", ""),
                author=rf.__dict__.get("author", ""),
                file_path=rf.file_path,
                line_number=rf.line_number,
                rule_name=rf.rule_name,
                severity=rf.severity,
                description=rf.description,
                matched_value_masked=masked_val,
                line_content_masked=masked_line,
            )
            db.add(finding)

        scan.commits_scanned = len(scanned_shas)
        scan.findings_count = len(raw_findings)
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

        # Update repo's last scanned commit
        repo = db.get(Repository, scan.repo_id)
        if repo and head_sha:
            repo.last_scanned_commit = head_sha
            db.commit()

    except Exception as e:
        db.rollback()
        try:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)[:1000]
                scan.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.get("/", response_model=list[ScanOut])
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    scans = (
        db.query(Scan)
        .options(joinedload(Scan.repository))
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )
    results = []
    for scan in scans:
        out = ScanOut.model_validate(scan)
        out.repo_name = scan.repository.name if scan.repository else None
        results.append(out)
    return results


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).options(joinedload(Scan.repository)).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    out = ScanOut.model_validate(scan)
    out.repo_name = scan.repository.name if scan.repository else None
    return out


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
def get_scan_findings(scan_id: int, show_resolved: bool = False, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if not show_resolved:
        q = q.filter(Finding.resolved == False)
    repo = db.get(Repository, scan.repo_id)
    results = []
    for f in q.order_by(Finding.id).all():
        out = FindingOut.model_validate(f)
        out.repo_name = repo.name if repo else None
        results.append(out)
    return results
