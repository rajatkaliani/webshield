"""
FastAPI server for web security scanning.

This API provides endpoints for scanning websites:
- POST /scan: Accepts URL or HTML/CSS/JS content, runs security scanners, returns results
- GET /health: Health check endpoint

The server fetches web pages, extracts CSS/JS resources, and runs security analysis.
Returns JSON with security score, issues list, and issue count.
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import os
import sys
import traceback

# Setup import paths
BASE_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, BASE_DIR)

from issue_dict import run_scan
from parser_utils import fetch_resources, parse_external_resources

app = FastAPI(title="WebShield Scan API")

# CORS for browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def handle_http_error(status_code, url):
    """Return appropriate HTTP exception based on status code."""
    error_messages = {
        403: "Access forbidden (403): The website blocked the scan request. This site may have bot protection or require authentication.",
        401: "Unauthorized (401): The website requires authentication to access.",
        404: "Not found (404): The URL could not be found.",
    }
    
    message = error_messages.get(status_code, f"HTTP {status_code} error: The server returned an error when trying to fetch the page.")
    raise HTTPException(status_code=status_code, detail=message)


@app.post("/scan")
async def scan(request: Request):
    """
    Scan a website for security issues.
    
    Accepts: { "url": "..." } or { "html": "...", "js": [...], "css": [...] }
    Returns: { "score": int, "issues": [...], "issue_count": int }
    """
    payload = await request.json()
    url = payload.get('url')
    html = payload.get('html')
    js_list = payload.get('js', []) or []
    css_list = payload.get('css', []) or []

    # Fetch HTML if URL provided
    if url and not html:
        # Check for unsupported URL types
        if url.startswith(('chrome://', 'chrome-extension://', 'moz-extension://', 'file://', 'about:')):
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot scan this type of URL: {url}. Please navigate to a regular website (http:// or https://)."
            )
        
        try:
            # Fetch HTML
            html, status_code = fetch_resources(url)
            if not html:
                if status_code:
                    handle_http_error(status_code, url)
                else:
                    raise HTTPException(
                        status_code=500, 
                        detail=f"Failed to fetch URL: {url}. The server could not download the page. It may be unreachable or blocked."
                    )
            
            # Extract and fetch external CSS/JS files
            resources = parse_external_resources(html, url)
            
            # Add internal styles/scripts
            if not css_list:
                css_list = resources.get("internal_styles", [])
            if not js_list:
                js_list = resources.get("internal_scripts", [])
            
            # Fetch external CSS files
            for css_url in resources.get("external_css_files", []):
                css_content, _ = fetch_resources(css_url)
                if css_content:
                    css_list.append(css_content)
            
            # Fetch external JS files
            for js_url in resources.get("external_js_files", []):
                js_content, _ = fetch_resources(js_url)
                if js_content:
                    js_list.append(js_content)
                    
        except HTTPException:
            raise
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Failed to fetch URL {url}: {str(e)}")

    if not html:
        raise HTTPException(status_code=400, detail="No HTML provided and no URL fetch succeeded")

    # Run security scan
    try:
        result = run_scan(html, js_list, css_list, page_url=url)
        return result
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"ok": True}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('scan_api:app', host='0.0.0.0', port=8000, reload=True)
