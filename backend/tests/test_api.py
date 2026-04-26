"""Tests for the FastAPI endpoints."""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.main import app

# ── In-memory SQLite test DB ───────────────────────────────────────────────

# StaticPool ensures all connections share the same in-memory database
_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestSession = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


def override_get_db():
    db = _TestSession()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.create_all(bind=_engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(bind=_engine)
    app.dependency_overrides.clear()


@pytest.fixture
def client(fresh_db):
    return TestClient(app)


@pytest.fixture
def local_repo(tmp_path):
    """A minimal git repo in a temp dir."""
    import git
    r = git.Repo.init(tmp_path)
    f = tmp_path / "secret.py"
    f.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    r.index.add(["secret.py"])
    r.index.commit("add secret", author=git.Actor("test", "t@t.com"),
                   committer=git.Actor("test", "t@t.com"))
    return str(tmp_path)


# ── Repos API ─────────────────────────────────────────────────────────────

class TestCreateRepo:
    def test_create_with_local_path(self, client, local_repo):
        r = client.post("/api/repos/", json={"path": local_repo})
        assert r.status_code == 201
        data = r.json()
        assert data["path"] == local_repo
        assert data["name"] == os.path.basename(local_repo)
        assert data["remote_url"] is None

    def test_create_with_remote_url(self, client):
        r = client.post("/api/repos/", json={"remote_url": "https://github.com/owner/myrepo"})
        assert r.status_code == 201
        data = r.json()
        assert data["remote_url"] == "https://github.com/owner/myrepo"
        assert data["name"] == "myrepo"
        assert data["path"].endswith(str(data["id"]))  # managed clone path

    def test_name_derived_from_url_strips_git_suffix(self, client):
        r = client.post("/api/repos/", json={"remote_url": "https://github.com/owner/myrepo.git"})
        assert r.json()["name"] == "myrepo"

    def test_create_requires_path_or_url(self, client):
        r = client.post("/api/repos/", json={"name": "no-source"})
        assert r.status_code == 400

    def test_create_local_path_must_exist(self, client):
        r = client.post("/api/repos/", json={"path": "/nonexistent/path/xyz"})
        assert r.status_code == 400

    def test_create_sets_default_monitor_off(self, client, local_repo):
        r = client.post("/api/repos/", json={"path": local_repo})
        assert r.json()["monitor_enabled"] is False


class TestListRepos:
    def test_empty_list(self, client):
        r = client.get("/api/repos/")
        assert r.status_code == 200
        assert r.json() == []

    def test_returns_added_repos(self, client, local_repo):
        client.post("/api/repos/", json={"path": local_repo})
        repos = client.get("/api/repos/").json()
        assert len(repos) == 1
        assert repos[0]["path"] == local_repo


class TestGetRepo:
    def test_get_existing(self, client, local_repo):
        created = client.post("/api/repos/", json={"path": local_repo}).json()
        r = client.get(f"/api/repos/{created['id']}")
        assert r.status_code == 200
        assert r.json()["id"] == created["id"]

    def test_get_missing_returns_404(self, client):
        assert client.get("/api/repos/9999").status_code == 404


class TestUpdateRepo:
    def test_update_monitor_enabled(self, client, local_repo):
        created = client.post("/api/repos/", json={"path": local_repo}).json()
        r = client.patch(f"/api/repos/{created['id']}", json={"monitor_enabled": True})
        assert r.status_code == 200
        assert r.json()["monitor_enabled"] is True

    def test_update_missing_returns_404(self, client):
        assert client.patch("/api/repos/9999", json={"monitor_enabled": True}).status_code == 404


class TestDeleteRepo:
    def test_delete_existing(self, client, local_repo):
        created = client.post("/api/repos/", json={"path": local_repo}).json()
        r = client.delete(f"/api/repos/{created['id']}")
        assert r.status_code == 204
        assert client.get(f"/api/repos/{created['id']}").status_code == 404

    def test_delete_missing_returns_404(self, client):
        assert client.delete("/api/repos/9999").status_code == 404


# ── Scan trigger ──────────────────────────────────────────────────────────

class TestTriggerScan:
    def test_trigger_creates_scan(self, client, local_repo):
        repo_id = client.post("/api/repos/", json={"path": local_repo}).json()["id"]
        r = client.post(f"/api/repos/{repo_id}/scan")
        assert r.status_code == 202
        assert "scan_id" in r.json()

    def test_trigger_missing_repo_returns_404(self, client):
        assert client.post("/api/repos/9999/scan").status_code == 404


# ── Scans API ─────────────────────────────────────────────────────────────

class TestScansAPI:
    def test_list_scans_empty(self, client):
        assert client.get("/api/scans/").json() == []

    def test_scan_appears_in_list(self, client, local_repo):
        repo_id = client.post("/api/repos/", json={"path": local_repo}).json()["id"]
        client.post(f"/api/repos/{repo_id}/scan")
        scans = client.get("/api/scans/").json()
        assert len(scans) >= 1
        assert scans[0]["repo_id"] == repo_id

    def test_get_scan_by_id(self, client, local_repo):
        repo_id = client.post("/api/repos/", json={"path": local_repo}).json()["id"]
        scan_id = client.post(f"/api/repos/{repo_id}/scan").json()["scan_id"]
        r = client.get(f"/api/scans/{scan_id}")
        assert r.status_code == 200
        assert r.json()["id"] == scan_id

    def test_get_missing_scan_returns_404(self, client):
        assert client.get("/api/scans/9999").status_code == 404


# ── Findings API ──────────────────────────────────────────────────────────

class TestFindingsAPI:
    def test_list_findings_empty(self, client):
        assert client.get("/api/findings/").json() == []

    def test_stats_all_zero(self, client):
        r = client.get("/api/findings/stats")
        assert r.status_code == 200
        s = r.json()
        assert s["total_repos"] == 0
        assert s["total_findings"] == 0

    def test_stats_counts_repos(self, client, local_repo):
        client.post("/api/repos/", json={"path": local_repo})
        assert client.get("/api/findings/stats").json()["total_repos"] == 1

    def test_filter_by_severity(self, client):
        r = client.get("/api/findings/?severity=critical")
        assert r.status_code == 200
        assert r.json() == []

    def test_filter_by_repo_id(self, client, local_repo):
        client.post("/api/repos/", json={"path": local_repo})
        r = client.get("/api/findings/?repo_id=1")
        assert r.status_code == 200
