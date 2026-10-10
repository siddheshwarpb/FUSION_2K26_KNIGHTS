#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting PatchOrder React UI on http://localhost:5173..."
exec npm --prefix "$DIR/frontend" run dev -- --host

