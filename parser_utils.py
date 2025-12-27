"""
Parser utilities for fetching and extracting web resources.

This module handles:
1. Fetching HTML, CSS, and JS files from URLs (with proper browser headers)
2. Extracting external CSS/JS file URLs from HTML
3. Parsing CSS rules and inline styles
4. Returning structured data for security scanning

All functions are synchronous and return simple data structures.
"""
import requests
from bs4 import BeautifulSoup
import cssutils
import logging
from urllib.parse import urljoin

logging.getLogger("cssutils").setLevel(logging.CRITICAL)


def fetch_resources(url):
    """
    Fetch HTML, CSS, or JS content from a URL.
    
    Uses realistic browser headers to avoid blocking.
    Returns (content, status_code) tuple. content is None on failure.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    
    try:
        response = requests.get(url, timeout=15, headers=headers, allow_redirects=True)
        response.raise_for_status()
        return (response.text, response.status_code)
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else None
        print(f"[ERROR] HTTP {status_code} error fetching URL ({url}): {e}")
        return (None, status_code)
    except requests.exceptions.Timeout:
        print(f"[ERROR] Timeout fetching URL ({url})")
        return (None, None)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Connection error fetching URL ({url})")
        return (None, None)
    except Exception as e:
        print(f"[ERROR] Error fetching URL ({url}): {e}")
        return (None, None)


def parse_external_resources(html, base_url):
    """
    Extract CSS and JS resources from HTML.
    
    Returns dict with:
    - internal_styles: List of <style> block contents
    - internal_scripts: List of inline <script> contents
    - external_css_files: List of CSS file URLs
    - external_js_files: List of JS file URLs
    - css_rules: Parsed CSS rules (not used by scanner, kept for compatibility)
    - js_sources: External JS file contents (not used by scanner, kept for compatibility)
    """
    soup = BeautifulSoup(html, "lxml")
    internal_styles = []
    internal_scripts = []
    external_css_files = []
    external_js_files = []

    for el in soup.find_all():
        tag = el.name
        attrs = el.attrs

        if tag == "style" and el.string:
            internal_styles.append(el.string)
        elif tag == "script":
            if attrs.get("src"):
                external_js_files.append(urljoin(base_url, attrs["src"]))
            elif el.string:
                internal_scripts.append(el.string)
        elif tag == "link" and attrs.get("rel") == ["stylesheet"]:
            external_css_files.append(urljoin(base_url, attrs["href"]))

    # Fetch external CSS files
    css_rules = []
    for css_url in external_css_files:
        css_text, _ = fetch_resources(css_url)
        if css_text:
            css_rules.extend(parse_css_rules(css_text))

    # Fetch external JS files
    js_sources = []
    for js_url in external_js_files:
        js_text, _ = fetch_resources(js_url)
        if js_text:
            js_sources.append({"url": js_url, "content": js_text[:5000]})

    return {
        "internal_styles": internal_styles,
        "internal_scripts": internal_scripts,
        "external_css_files": external_css_files,
        "external_js_files": external_js_files,
        "css_rules": css_rules,
        "js_sources": js_sources
    }


def parse_css_rules(css_text):
    """Parse CSS stylesheet into structured rules. Used for compatibility."""
    rules = []
    try:
        sheet = cssutils.parseString(css_text)
        for rule in sheet:
            if rule.type == rule.STYLE_RULE:
                properties = {decl.name: decl.value for decl in rule.style}
                rules.append({"selectors": rule.selectorText, "properties": properties})
    except Exception:
        pass
    return rules
