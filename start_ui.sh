#!/bin/bash
# Start claudebbp Web UI
cd "$(dirname "$0")"

echo ""
echo "  Installing UI dependencies..."
pip install fastapi uvicorn python-multipart 2>/dev/null | grep -E "(Successfully|already)"

echo ""
echo "  Starting claudebbp UI → http://localhost:8080"
echo "  Press Ctrl+C to stop"
echo ""

python -m uvicorn ui.server:app --host 0.0.0.0 --port 8080 --reload --log-level warning
