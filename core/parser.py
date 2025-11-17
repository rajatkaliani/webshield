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
# Fetch All resources
# =========================
def fetch_resources(url: str) -> str:
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
# Parses External CSS file
# =========================
def parse_css_rules(css_text: str) -> list:
    rules = []
    try:
        sheet = cssutils.parseString(css_text)
        for rule in sheet:
            if rule.type == rule.STYLE_RULE:
                selectors = rule.selectorText
                props = {}

                for style in rule.style:
                    props[style.name] = style.value

                rules.append({
                    "selectors": selectors,
                    "properties": props
                })
    except Exception:
        pass

    return rules


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
# Extract external & internal CSS/JS resources
# =========================
def parse_external_resources(html: str, base_url: str):
    soup = BeautifulSoup(html, "lxml")

    internal_styles = []
    internal_scripts = []
    external_css_files = []
    external_js_files = []

    # Scan through all tags
    for el in soup.find_all():
        tag = el.name
        attrs = el.attrs

        # <style>...</style>
        if tag == "style" and el.string:
            internal_styles.append(el.string)

        # <script>...</script> (inline)
        if tag == "script":
            if attrs.get("src"):
                # external JS
                abs_js = urljoin(base_url, attrs["src"])
                external_js_files.append(abs_js)
            else:
                # inline JS block
                if el.string:
                    internal_scripts.append(el.string)

        # <link rel="stylesheet" href="...">
        if tag == "link" and attrs.get("rel") == ["stylesheet"]:
            href = attrs.get("href")
            if href:
                abs_css = urljoin(base_url, href)
                external_css_files.append(abs_css)

    # Download and parse CSS files
    css_rules = []
    for css_url in external_css_files:
        css_text = fetch_resources(css_url)
        if css_text:
            css_rules.extend(parse_css_rules(css_text))

    # Download JS files
    js_sources = []
    for js_url in external_js_files:
        js_text = fetch_resources(js_url)
        if js_text:
            js_sources.append({
                "url": js_url,
                "content": js_text[:5000]  # limit for debugging
            })

    return {
        "internal_styles": internal_styles,
        "internal_scripts": internal_scripts,
        "external_css_files": external_css_files,
        "external_js_files": external_js_files,
        "css_rules": css_rules,
        "js_sources": js_sources
    }

# =========================
# Parse URL (main function)
# =========================
def parse_url(url: str) -> list:
    print(f"[INFO] Fetching URL: {url}")
    html = fetch_resources(url)

    if not html:
        return []

    print("[INFO] Parsing DOM (inline CSS & JS)...")
    elements = extract_dom_elements(html, base_url=url)

    print("[INFO] Parsing external CSS & JS...")
    resources = parse_external_resources(html, base_url=url)

    print(f"[INFO] Extracted {len(elements)} elements.")
    print(f"[INFO] Found {len(resources['external_css_files'])} external CSS files.")
    print(f"[INFO] Found {len(resources['external_js_files'])} external JS files.")

    return {
        "elements": elements,
        **resources
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Invalid input: needs to be a URL python3 parser.py https://www.hello.com/")
        sys.exit(1)

    url = sys.argv[1]
    elements = parse_url(url)

    # Show a few elements for debugging
    for i, el in enumerate(elements[:3]):
        print("\n=== SUMMARY ===")
        print("Total elements:", len(result["elements"]))
        print("Inline <style> blocks:", len(result["internal_styles"]))
        print("Inline <script> blocks:", len(result["internal_scripts"]))
        print("External CSS files:", len(result["external_css_files"]))
        print("External JS files:", len(result["external_js_files"]))
        print("CSS rules parsed:", len(result["css_rules"]))
        print("JS files fetched:", len(result["js_sources"]))