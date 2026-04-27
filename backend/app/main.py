import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from apscheduler.schedulers.background import BackgroundScheduler

from .database import engine, Base, SessionLocal
from .models import Repository, Scan
from .routers import repos, scans, findings
from .routers.scans import run_scan


def monitor_repos():
    """Periodic job: trigger scans for repos with monitoring enabled."""
    db = SessionLocal()
    try:
        repos_to_monitor = db.query(Repository).filter(Repository.monitor_enabled == True).all()
        for repo in repos_to_monitor:
            # Check if there's already a running scan for this repo
            running = (
                db.query(Scan)
                .filter(Scan.repo_id == repo.id, Scan.status.in_(["pending", "running"]))
                .first()
            )
            if running:
                continue

            scan = Scan(repo_id=repo.id, status="pending")
            db.add(scan)
            db.commit()
            db.refresh(scan)
            # Run inline (scheduler thread is fine for short scans)
            run_scan(scan.id, repo.path, repo.last_scanned_commit, repo.remote_url, depth="incremental", branch="all")
    finally:
        db.close()


scheduler = BackgroundScheduler()


def _migrate():
    """Add columns introduced after initial schema creation."""
    from sqlalchemy import text
    with engine.connect() as conn:
        for stmt in [
            "ALTER TABLE findings ADD COLUMN resolved BOOLEAN DEFAULT FALSE",
            "ALTER TABLE findings ADD COLUMN resolved_at DATETIME",
            "ALTER TABLE scans ADD COLUMN commits_total INTEGER DEFAULT 0",
            "ALTER TABLE scans ADD COLUMN commits_done INTEGER DEFAULT 0",
        ]:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass  # column already exists


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _migrate()
    scheduler.add_job(monitor_repos, "interval", minutes=5, id="monitor_repos")
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="DiffScan", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(repos.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(findings.router, prefix="/api")

# Serve the frontend
_frontend_dir = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
_frontend_dir = os.path.abspath(_frontend_dir)

if os.path.isdir(_frontend_dir):
    app.mount("/static", StaticFiles(directory=_frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    def serve_index():
        return FileResponse(os.path.join(_frontend_dir, "index.html"))
