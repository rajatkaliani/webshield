# WebShield (local developer setup)

This repository contains a rule-based web UI security scanner and a small extension popup that posts a URL to a local scanning API.

Quick start (macOS / Linux)

1. Create and activate a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
# Install Playwright browser binaries (required if renderer is used):
python3 -m playwright install --with-deps
```

3. Run the API server (development):

```bash
# From the repo root
uvicorn scan_api:app --reload --host 0.0.0.0 --port 8000
```

4. Test the endpoint:

```bash
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" -d '{"url":"https://news.ycombinator.com/"}'
```

If `curl` fails with "Couldn't connect", it means the server process isn't running or is blocked by firewall — see troubleshooting below.

Troubleshooting

- If you see import errors when starting the server, ensure you're running from the repository root so Python can find the `backend/` and project modules.
- Check the server process and listening ports:

```bash
# macOS
lsof -nP -iTCP:8000 -sTCP:LISTEN

# or
netstat -an | grep 8000
```

- If the extension popup shows CORS errors when calling the API, ensure the server is running and returning appropriate CORS headers; `scan_api.py` enables permissive CORS for local development.

Next steps

- If you want, I can add a small `run_server.sh` script, or convert `backend/` into a proper Python package to improve imports and linting.
