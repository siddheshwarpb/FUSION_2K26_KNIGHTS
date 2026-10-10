#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$DIR/backend"

echo "Starting PatchOrder FastAPI Backend on http://localhost:8000..."
exec "$DIR/backend/venv/bin/uvicorn" app.main:app --host 0.0.0.0 --port 8000 --reload

