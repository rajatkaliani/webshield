# WebShield - Simple Web Security Scanner

A simple, functional web security scanner that parses HTML/CSS/JS, analyzes each token against security rules, and stores issues.

## How It Works

1. **Parse**: Extract HTML, CSS, and JavaScript from a webpage
2. **Analyze**: Check each element/token against security rules
3. **Store**: Collect issues and compute security score

## Quick Start

1. Create and activate virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the API server:
```bash
uvicorn scan_api:app --reload --host 0.0.0.0 --port 8000
```

4. Test the endpoint:
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Project Structure

```
WebSecProject/
├── backend/
│   ├── html_scanner.py    # Parse HTML, analyze elements, store issues
│   ├── js_scanner.py      # Parse JS, analyze patterns, store issues
│   ├── css_scanner.py     # Parse CSS, analyze rules, store issues
│   └── issue_dict.py      # Orchestrates scanning and scoring
├── extension/             # Browser extension (Chrome/Edge)
│   ├── popup.html
│   ├── popup.js
│   └── manifest.json
├── scan_api.py           # FastAPI server (synchronous, no async)
├── parser_utils.py        # Simple fetch and extract functions
└── requirements.txt
```

## Usage

### API Endpoint

**POST /scan**

Accepts:
- `{"url": "https://example.com"}` - Fetches page and all external resources
- `{"html": "...", "js": [...], "css": [...]}` - Direct content

Returns:
```json
{
  "score": 85,
  "issues": [
    {
      "issue": "Inline JavaScript detected",
      "severity": "medium",
      "category": "malicious_js"
    }
  ],
  "issue_count": 3
}
```

### Browser Extension

1. Load the extension from the `extension/` folder
2. Navigate to any website
3. Click the extension icon and press "Scan Site"
4. View the security score

## Security Rules

The scanner checks for:
- **HTML**: Inline JS, deprecated tags, hidden elements, clickjacking, fake links
- **JavaScript**: eval(), obfuscation, crypto mining, redirects, DOM injection
- **CSS**: Hidden elements, offscreen positioning, pointer-events tricks

## Scoring

- Starts at 100 points
- Low severity: -2 points
- Medium severity: -5 points  
- High severity: -10 points
- Minimum score: 0
