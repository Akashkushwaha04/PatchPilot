#!/usr/bin/env bash
# One-command start: installs deps if needed, builds the UI, serves everything on :8000.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then set -a; . ./.env; set +a; fi

python3 -m pip install -q -r backend/requirements.txt

if [ ! -f frontend/dist/index.html ] || [ "${REBUILD:-0}" = "1" ]; then
  (cd frontend && npm install --no-audit --no-fund && npm run build)
fi

echo "PatchPilot AI running at http://localhost:8000  (API docs: /docs)"
cd backend && exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
