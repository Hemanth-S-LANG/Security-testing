# SecureTester

**Automated OWASP Top 10 Security Testing Platform for REST APIs**

Upload a Swagger/OpenAPI spec, provide a base URL, and SecureTester automatically generates and runs hundreds of security test cases — no manual setup required.

---

## Features

- **Automatic test generation** from any Swagger/OpenAPI JSON spec
- **5 OWASP categories** tested out of the box:
  - A01: Broken Access Control (IDOR, path traversal, mass assignment)
  - A03: Injection (SQL, NoSQL, template injection)
  - A05: Security Misconfiguration (headers, CORS, exposed files)
  - A07: Broken Authentication (JWT, default creds, missing auth)
  - A03: Input Validation (XSS, buffer overflow, CRLF, format strings)
- **Real response analysis** — backend sends actual HTTP requests and analyzes responses
- **Multi-user support** — each user has isolated projects and results
- **Analytics dashboard** — donut chart, severity bars, OWASP category breakdown
- **Expandable result rows** — see payload used, HTTP status, vulnerability detail, recommendation

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | React 18 + Vite + React Router |
| Backend | FastAPI + SQLAlchemy (async) + httpx |
| Database | PostgreSQL 16 |
| Auth | JWT via python-jose + bcrypt |
| HTTP Testing | httpx (async, concurrent) |

---

## Quickstart (Docker — recommended)

```bash
git clone <repo>
cd securetester
docker-compose up --build
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

---

## Manual Setup

### Backend

```bash
cd backend

# Create virtualenv
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install deps
pip install -r requirements.txt

# Create .env
cp .env.example .env
# Edit DATABASE_URL and SECRET_KEY

# Start PostgreSQL (or use Docker just for DB)
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_DB=securetester postgres:16-alpine

# Run backend (tables auto-created on startup)
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## Environment Variables

Create `backend/.env`:

```env
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/securetester
SYNC_DATABASE_URL=postgresql://postgres:password@localhost:5432/securetester
SECRET_KEY=your-very-secret-key-change-this
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
REDIS_URL=redis://localhost:6379/0
MAX_CONCURRENT_REQUESTS=10
REQUEST_TIMEOUT_SECONDS=30
CORS_ORIGINS=["http://localhost:5173"]
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | /api/auth/register | Create account |
| POST | /api/auth/login | Get JWT token |
| GET | /api/auth/me | Current user |
| POST | /api/projects | Create project with swagger spec |
| GET | /api/projects | List user's projects |
| POST | /api/projects/{id}/generate | Preview test cases |
| POST | /api/projects/{id}/run | Execute all tests |
| GET | /api/projects/{id}/runs | List past runs |
| GET | /api/runs/{id}/results | Full results + analytics |

---

## Security Testing Logic

### How it works

1. **Parse** — Extract all paths, methods, parameters from the Swagger spec
2. **Generate** — For each endpoint × each OWASP payload → one test case
3. **Execute** — Send real HTTP requests concurrently using httpx (bounded by semaphore)
4. **Analyze** — Inspect response: status code, body patterns, headers
5. **Classify** — PASS / FAIL / ERROR + severity + recommendation
6. **Store** — Persist all results to PostgreSQL

### Detection logic per category

**SQL Injection** — Looks for SQL error strings (`mysql_fetch`, `ORA-`, `quoted string not properly terminated`, etc.) in the response body. Also detects 500 errors triggered by SQL payloads.

**Broken Authentication** — Checks if JWT with `alg:none` is accepted, if endpoints return 200 without auth headers, if default credentials succeed.

**Broken Access Control** — Checks for path traversal success (file content in response), privilege escalation (role fields changed), IDOR on enumerable IDs.

**Security Misconfiguration** — Checks response headers for `x-content-type-options`, `strict-transport-security`, `content-security-policy`, etc. Also checks for CORS wildcard and stack traces.

**Input Validation** — Checks if XSS payloads are reflected in response body, if template injection expressions evaluate (`{{7*7}}` → `49`), if CRLF injection works.

---

## Database Schema

```
users
  └── projects (swagger_spec stored as JSONB)
        └── test_runs (status, pass/fail counts, duration)
              └── test_cases (endpoint, method, payload, owasp_category)
                    └── test_results (status, http_code, response_body, vuln_detail)
```

---

## Concurrency

Tests run with `asyncio.gather()` bounded by a semaphore (`MAX_CONCURRENT_REQUESTS=10`). This means 10 requests fly in parallel at any time, keeping load manageable while still being fast.

---

## Disclaimer

This tool is for **authorized security testing only**. Only test APIs you own or have explicit written permission to test. Unauthorized testing is illegal.