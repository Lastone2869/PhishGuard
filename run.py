"""
run.py
Single entrypoint to start the PhishGuard application server.
Run with: python run.py
"""

import sys
import os
import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("  PhishGuard AI — Starting Server (Stage 1 Core)")
    print("  Web Interface: http://127.0.0.1:8000")
    print("  API Docs:      http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
