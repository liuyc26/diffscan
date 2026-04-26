# diffscan

A lightweight secret and token scanner for git repositories. Scans commit diffs for leaked API keys, credentials, private keys, and other sensitive values.

![diffscan screenshot](https://raw.githubusercontent.com/liuyc26/diffscan/main/docs/screenshot.png)

## Features

- **33 named rules** — AWS, GCP, Azure, GitHub/GitLab tokens, Stripe, SendGrid, Twilio, Slack, Discord, PEM/PGP keys, JWTs, DB connection strings, and more
- **Entropy detection** — catches high-entropy strings that evade named rules
- **Flexible scan depth** — latest commit, since last scan, last N commits, or full history
- **Branch targeting** — scan a specific branch, HEAD, or all branches at once
- **Background monitoring** — auto-scan repos on a configurable interval
- **Resolve findings** — dismiss false positives so they stop cluttering results
- **Secret masking** — matched values are stored and displayed masked

## Quick start

### Local (SQLite, no Docker needed)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000

### Docker Compose (PostgreSQL)

```bash
docker compose up --build
```

Open http://localhost:8000

## Usage

1. **Add a repo** — paste a local path or GitHub URL in the Repositories tab and press Enter
2. **Scan** — choose branch and depth, then click "Scan now"
3. **Review findings** — click any scan row to open the findings panel
4. **Resolve** — click "Resolve" on a finding to dismiss it; toggle "Show resolved" to review dismissed items
5. **Monitor** — click the monitor button on a repo to enable automatic background scanning

## Development

```bash
cd backend
pytest tests/ -v
```

All 80 tests should pass.

## Tech stack

- **Backend** — FastAPI, SQLAlchemy, GitPython, APScheduler
- **Database** — SQLite (dev) / PostgreSQL (prod)
- **Frontend** — Vanilla JS, Tailwind CSS CDN

## License

MIT
