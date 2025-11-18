import requests
from bs4 import BeautifulSoup
import cssutils
import logging
from urllib.parse import urljoin

logging.getLogger("cssutils").setLevel(logging.CRITICAL)


# =====================================================
# 1. FETCHING LAYER — raw network access
# =====================================================
def fetch_resources(url: str) -> str:
    """Download raw text of ANY webpage, CSS file, or JS file."""
    try:
        response = requests.get(url, timeout=10, headers={
            "User-Agent": "Mozilla/5.0"
        })
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"[ERROR] Failed to fetch URL ({url}): {e}")
        return None


# =====================================================
# 2. EXTRACTION LAYER — pull raw chunks from HTML
# =====================================================
def extract_dom_elements(html: str, base_url: str = None) -> list:
    """Extract HTML elements + inline CSS/JS attributes."""
    soup = BeautifulSoup(html, "lxml")
    elements = []

    for el in soup.find_all(True):
        inline_script = None
        if el.name == "script" and not el.attrs.get("src"):
            inline_script = el.string

        href = el.attrs.get("href")
        if href and base_url:
            href = urljoin(base_url, href)

        elements.append({
            "tag": el.name,
            "text": el.get_text(strip=True)[:200],
            "attributes": el.attrs,
            "inline_css": parse_inline_css(el.attrs.get("style")),
            "onclick": el.attrs.get("onclick"),
            "inline_script": inline_script,
            "href": href,
            "html_snippet": str(el)[:300]
        })

    return elements


def parse_external_resources(html: str, base_url: str):
    """Extract <style> blocks, external CSS URLs, external JS URLs."""
    soup = BeautifulSoup(html, "lxml")

    internal_styles = []
    internal_scripts = []
    external_css_files = []
    external_js_files = []

    for el in soup.find_all():
        tag = el.name
        attrs = el.attrs

        # <style>
        if tag == "style" and el.string:
            internal_styles.append(el.string)

        # <script>
        if tag == "script":
            if attrs.get("src"):
                external_js_files.append(urljoin(base_url, attrs["src"]))
            elif el.string:
                internal_scripts.append(el.string)

        # <link rel="stylesheet">
        if tag == "link" and attrs.get("rel") == ["stylesheet"]:
            external_css_files.append(urljoin(base_url, attrs["href"]))

    # Fetch CSS files + parse rules
    css_rules = []
    for css_url in external_css_files:
        css_text = fetch_resources(css_url)
        if css_text:
            css_rules.extend(parse_css_rules(css_text))

    # Fetch external JS content
    js_sources = []
    for js_url in external_js_files:
        js_text = fetch_resources(js_url)
        if js_text:
            js_sources.append({
                "url": js_url,
                "content": js_text[:5000]
            })

    return {
        "internal_styles": internal_styles,
        "internal_scripts": internal_scripts,
        "external_css_files": external_css_files,
        "external_js_files": external_js_files,
        "css_rules": css_rules,
        "js_sources": js_sources
    }


# =====================================================
# 3. PARSING LAYER — interpret CSS / other content
# =====================================================
def parse_inline_css(style_value: str) -> dict:
    """Turn inline CSS text into a property dictionary."""
    if not style_value:
        return {}

    css_props = {}
    try:
        parsed = cssutils.parseStyle(style_value)
        for prop in parsed:
            css_props[prop.name] = prop.value
    except Exception:
        pass

    return css_props


def parse_css_rules(css_text: str) -> list:
    """Parse an entire CSS stylesheet into structured rules."""
    rules = []

    try:
        sheet = cssutils.parseString(css_text)
        for rule in sheet:
            if rule.type == rule.STYLE_RULE:
                properties = {decl.name: decl.value for decl in rule.style}
                rules.append({
                    "selectors": rule.selectorText,
                    "properties": properties
                })
    except Exception:
        pass

    return rules