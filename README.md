# ESP — Enterprise Security Platform 🔐

**ESP** is an open-source vulnerability scanning and threat-intelligence platform that includes a Python backend (APIs, ingestion, processing) and a TypeScript frontend (Vite + React). The repo contains automation, tests, and tooling to run locally or via Docker.

---

## Contents
- `backend/` — Python API, scan ingestors, intelligence layer, tests
- `frontend/` — Vite + React UI written in TypeScript
- `chroma_db/` — local Chroma DB files (development/test data)
- `data/` — threat feed JSON dumps
- `mds/`, `temp/`, `docs/` — docs and working files

---

## Quick start (development) ⚙️

### Prerequisites
- Git
- Python 3.11 (recommended)
- Node.js 18+ / npm or yarn
- (Optional) Docker & Docker Compose for containerized services

### Backend
1. Create and activate a virtual environment:

```bash
python -m venv venv
# Windows (PowerShell)
venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate
```

2. Install Python dependencies:

```bash
pip install -r backend/requirements.txt
```

3. Copy or create environment variables (do not commit `.env`):

```bash
cp backend/.env.example .env  # or reference backend/.env.example.new
# Edit .env for DB URLs, API keys, etc.
```

4. Run API locally (development):

```bash
cd backend
python run_api.py
# or use the provided scripts such as start_services.ps1 on Windows
```

5. Run tests:

```bash
cd backend
pytest
```

### Frontend
1. Install dependencies:

```bash
cd frontend
npm install
# or
# yarn
```

2. Run in dev mode:

```bash
npm run dev
```

3. Build for production:

```bash
npm run build
```

---

## Docker (recommended for integration)
- See `backend/docker-compose.yml` to start backend services and dependencies.
- The `frontend` folder also has a `Dockerfile` and `nginx.conf` for containerized deployment.

---

## Data & Local DBs
- Local DB files like `chroma_db/chroma.sqlite3` or `test_chroma_db/chroma.sqlite3` and dumps like `dump.rdb` are intentionally **not** tracked. They are added to `.gitignore` to avoid bloating the repo.
- If you need to seed test data, check `temp/test_files/` or `data/threat_feeds/`.

---

## Important notes ✅
- Do not commit `venv/`, `.env`, generated `.sqlite3` files, or other local artifacts. They are in `.gitignore`.
- If you accidentally committed large files, notify collaborators before rewriting history to remove them.

---

## Contributing
- Fork or branch and open a pull request. Follow existing code style and tests.
- Run `pytest` for backend tests and the frontend test suite if added.

---

## License & Contact
- See `mds/COPYRIGHT_AND_PATENT.md` and repo metadata for licensing and legal information.
- For questions, open an issue or contact repository maintainers.

---

Happy hacking! 🚀
