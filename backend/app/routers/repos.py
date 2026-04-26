import os
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Repository, Scan, Finding
from ..schemas import RepoCreate, RepoUpdate, RepoOut
from . import scans as scans_router

router = APIRouter(prefix="/repos", tags=["repos"])


@router.get("/", response_model=list[RepoOut])
def list_repos(db: Session = Depends(get_db)):
    return db.query(Repository).order_by(Repository.created_at.desc()).all()


_CLONES_DIR = os.path.expanduser("~/.diffscan/clones")


def _is_url(s: str) -> bool:
    return s.startswith(("https://", "http://", "git@", "ssh://"))


def _derive_name(source: str) -> str:
    return source.rstrip("/").rstrip(".git").split("/")[-1] or source


@router.post("/", response_model=RepoOut, status_code=201)
def create_repo(body: RepoCreate, db: Session = Depends(get_db)):
    if not body.path and not body.remote_url:
        raise HTTPException(status_code=400, detail="Provide either a local path or a remote URL.")

    if body.remote_url:
        # Remote repo: clone path will be assigned after we know the id
        repo = Repository(
            name=body.name or _derive_name(body.remote_url),
            remote_url=body.remote_url,
            path="",  # filled in below
            description=body.description,
            monitor_enabled=body.monitor_enabled,
            monitor_interval_minutes=body.monitor_interval_minutes,
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)
        clone_path = os.path.join(_CLONES_DIR, str(repo.id))
        repo.path = clone_path
        db.commit()
        db.refresh(repo)
    else:
        if not os.path.isdir(body.path):
            raise HTTPException(status_code=400, detail=f"Path does not exist: {body.path}")
        repo = Repository(
            name=body.name or _derive_name(body.path),
            remote_url=None,
            path=body.path,
            description=body.description,
            monitor_enabled=body.monitor_enabled,
            monitor_interval_minutes=body.monitor_interval_minutes,
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)

    return repo


@router.get("/{repo_id}", response_model=RepoOut)
def get_repo(repo_id: int, db: Session = Depends(get_db)):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


@router.patch("/{repo_id}", response_model=RepoOut)
def update_repo(repo_id: int, body: RepoUpdate, db: Session = Depends(get_db)):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(repo, key, value)
    db.commit()
    db.refresh(repo)
    return repo


@router.delete("/{repo_id}", status_code=204)
def delete_repo(repo_id: int, db: Session = Depends(get_db)):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    db.delete(repo)
    db.commit()


@router.post("/{repo_id}/scan", status_code=202)
def trigger_scan(
    repo_id: int,
    background_tasks: BackgroundTasks,
    depth: str = Query(default="latest", description="latest | incremental | all | <N>"),
    branch: str = Query(default="", description="branch name, 'all', or '' for HEAD"),
    db: Session = Depends(get_db),
):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    scan = Scan(repo_id=repo_id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    since = repo.last_scanned_commit if depth == "incremental" else None
    background_tasks.add_task(scans_router.run_scan, scan.id, repo.path, since, repo.remote_url, depth, branch)
    return {"scan_id": scan.id, "status": "pending"}
