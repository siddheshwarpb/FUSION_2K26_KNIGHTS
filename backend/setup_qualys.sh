#!/usr/bin/env bash
# ==============================================================================
# PatchOrder — Qualys QScanner Setup & Verification Script
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QSCANNER_BIN="$SCRIPT_DIR/qscanner"

echo "=== PatchOrder Qualys Integration Setup ==="

# 1. Check if QScanner binary exists
if [ -f "$QSCANNER_BIN" ]; then
    echo "✔ Found QScanner binary at $QSCANNER_BIN"
    chmod +x "$QSCANNER_BIN"
else
    echo "ℹ QScanner binary not found at $QSCANNER_BIN"
    echo ""
    echo "To install QScanner CLI:"
    echo "1. Log into your Qualys Cloud Platform account."
    echo "2. Navigate to Container Security / TotalCloud > Code Security."
    echo "3. Download the QScanner binary for Linux (x86_64)."
    echo "4. Place it in: $QSCANNER_BIN"
    echo "5. Run: chmod +x $QSCANNER_BIN"
fi

# 2. Check .env configuration
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    echo "✔ Found $ENV_FILE"
else
    echo "ℹ Creating $ENV_FILE from .env.example..."
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
fi

echo ""
echo "=== Configuration Status ==="
echo "Edit '$ENV_FILE' to provide your credentials:"
echo "  QUALYS_PLATFORM=gateway.qg1.apps.qualys.com"
echo "  QUALYS_CLIENT_ID=<your-qualys-client-id>"
echo "  QUALYS_CLIENT_SECRET=<your-qualys-client-secret>"
echo "  QUALYS_QSCANNER_PATH=$QSCANNER_BIN"
echo ""
echo "Setup script completed."
