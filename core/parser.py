'''
File Fetches HTML grabbing all elements

Extracts metadata

Parses the inline CSS and JS


'''
import requests
from bs4 import BeautifulSoup
import cssutils
import logging
logging.getLogger('cssutils').setLevel(logging.CRITICAL)
from urllib.parse import urljoin

# =========================
# Fetch HTML
# =========================
def fetch_html(url: str) -> str:
    """Download the raw HTML of a webpage."""
    try:
        response = requests.get(url, timeout=10, headers={
            "User-Agent": "Mozilla/5.0"
        })
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"[ERROR] Failed to fetch URL: {e}")
        return None


# =========================
# Inline CSS Parsing
# =========================
def parse_inline_css(style_value: str) -> dict:
    """Parse inline CSS into a dictionary of properties."""
    if not style_value:
        return {}

    css_props = {}
    try:
        parsed = cssutils.parseStyle(style_value)
        for prop in parsed:
            css_props[prop.name] = prop.value
    except Exception:
        pass  # ignore any broken CSS

    return css_props


# =========================
# Extract elements + metadata
# =========================
def extract_dom_elements(html: str, base_url: str = None) -> list:
    """Extract HTML elements and associated metadata."""
    soup = BeautifulSoup(html, "lxml")
    elements_data = []

    for el in soup.find_all(True):
        tag = el.name
        text = el.get_text(strip=True)[:200]
        attrs = el.attrs

        # Inline styles
        inline_css = parse_inline_css(attrs.get("style"))

        # Inline JS (onclick)
        onclick = attrs.get("onclick")

        # Inline JS (script tags)
        inline_script = None
        if tag == "script" and not attrs.get("src"):
            inline_script = el.string

        # Links
        href = attrs.get("href")
        if href and base_url:
            href = urljoin(base_url, href)

        elements_data.append({
            "tag": tag,
            "text": text,
            "attributes": attrs,
            "inline_css": inline_css,
            "onclick": onclick,
            "inline_script": inline_script,
            "href": href,
            "html_snippet": str(el)[:300]
        })

    return elements_data


# =========================
# Parse URL (main function)
# =========================
def parse_url(url: str) -> list:
    print(f"[INFO] Fetching URL: {url}")
    html = fetch_html(url)

    if not html:
        return []

    print("[INFO] Parsing DOM (inline CSS & JS)...")
    elements = extract_dom_elements(html, base_url=url)

    print(f"[INFO] Extracted {len(elements)} elements.")
    return elements


# =========================
# CLI Entry Point
# =========================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python parser.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    elements = parse_url(url)

    # Show a few elements for debugging
    for i, el in enumerate(elements[:10]):
        print(f"\n---- Element #{i+1} ----")
        print("Tag: ", el["tag"])
        print("Text:", el["text"])
        print("Href:", el["href"])
        print("Inline CSS:", el["inline_css"])
        print("Onclick:", el["onclick"])
        print("Inline Script:", bool(el["inline_script"]))
        print("HTML Snippet:", el["html_snippet"])