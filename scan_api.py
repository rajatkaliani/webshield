from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import sys

# Setup paths
BASE_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, BASE_DIR)

from issue_dict import run_scan
from parser_utils import fetch_resources, fetch_and_extract_all

app = FastAPI(title="WebShield Scan API")

# CORS for extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/scan")
def scan_endpoint(request_data: dict):
    """Scan a website for security issues.
    
    Accepts: { "url": "..." } or { "html": "...", "js": [...], "css": [...] }
    Returns: { "score": int, "issues": [...], "issue_count": int }
    """
    url = request_data.get('url')
    html = request_data.get('html')
    js_list = request_data.get('js', [])
    css_list = request_data.get('css', [])

    # If URL provided, fetch HTML and all external CSS/JS
    if url and not html:
        data = fetch_and_extract_all(url)
        if not data:
            raise HTTPException(status_code=500, detail="Failed to fetch URL")
        html = data['html']
        if not js_list:
            js_list = data['js_list']
        if not css_list:
            css_list = data['css_list']

    if not html:
        raise HTTPException(status_code=400, detail="No HTML provided")

    # Run scan: parse -> analyze -> store results
    result = run_scan(html, js_list, css_list, page_url=url)
    return result


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"ok": True}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('scan_api:app', host='0.0.0.0', port=8000, reload=True)
