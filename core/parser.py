'''
Main function file to call all helpers from parser.utils displaying example of
what data will look like
'''
from parser_utils import (
    fetch_resources,
    extract_dom_elements,
    parse_external_resources
)
from core.dynamic_renderer import render_dynamic_dom

def parse_url(url: str) -> dict:
    """Full Phase 1 + Phase 2 parsing."""
    print(f"[INFO] Fetching URL: {url}")
    html = fetch_resources(url)

    if not html:
        return {}

    print("[INFO] Parsing inline HTML/CSS/JS (Phase 1)...")
    elements = extract_dom_elements(html, base_url=url)

    print("[INFO] Parsing external CSS/JS (Phase 2)...")
    resources = parse_external_resources(html, base_url=url)

    print(f"[INFO] Extracted {len(elements)} DOM elements.")
    print(f"[INFO] Found {len(resources['external_css_files'])} external CSS files.")
    print(f"[INFO] Found {len(resources['external_js_files'])} external JS files.")


    print("[INFO] Running dynamic renderer (Phase 3)...")
    rendered = render_dynamic_dom(url)

    return {
        "elements": elements,
        **resources,
        "rendered_elements": rendered
    }


# =========================
# Command-line usage
# =========================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 parser.py https://example.com")
        sys.exit(1)

    url = sys.argv[1]
    result = parse_url(url)

    print("\n=== SUMMARY ===")
    print("Total DOM elements:", len(result["elements"]))
    print("Inline <style> blocks:", len(result["internal_styles"]))
    print("Inline <script> blocks:", len(result["internal_scripts"]))
    print("External CSS files:", len(result["external_css_files"]))
    print("External JS files:", len(result["external_js_files"]))
    print("CSS rules parsed:", len(result["css_rules"]))
    print("JS files fetched:", len(result["js_sources"]))
    print("Rendered DOM elements:", len(result["rendered_elements"]))
