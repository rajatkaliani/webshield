"""
Simple parser utilities: fetch resources and extract basic content.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def fetch_resources(url):
    """
    Fetch HTML, CSS, or JS content from a URL.
    
    Returns content as string, or None if failed.
    """
    try:
        response = requests.get(url, timeout=10, headers={
            "User-Agent": "Mozilla/5.0"
        })
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"[ERROR] Failed to fetch {url}: {e}")
        return None


def extract_external_resources(html, base_url):
    """
    Extract external CSS and JS file URLs from HTML.
    
    Returns dict with 'css_urls' and 'js_urls' lists.
    """
    soup = BeautifulSoup(html, "html.parser")
    css_urls = []
    js_urls = []
    
    # Find external CSS files
    for link in soup.find_all("link"):
        if link.get("rel") == ["stylesheet"]:
            href = link.get("href")
            if href:
                css_urls.append(urljoin(base_url, href))
    
    # Find external JS files
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_urls.append(urljoin(base_url, src))
    
    return {
        "css_urls": css_urls,
        "js_urls": js_urls
    }


def fetch_and_extract_all(url):
    """
    Fetch HTML from URL, then fetch all external CSS/JS files.
    
    Returns dict with 'html', 'css_list', 'js_list'.
    """
    html = fetch_resources(url)
    if not html:
        return None
    
    resources = extract_external_resources(html, url)
    
    # Fetch all CSS files
    css_list = []
    for css_url in resources["css_urls"]:
        css_content = fetch_resources(css_url)
        if css_content:
            css_list.append(css_content)
    
    # Fetch all JS files
    js_list = []
    for js_url in resources["js_urls"]:
        js_content = fetch_resources(js_url)
        if js_content:
            js_list.append(js_content)
    
    return {
        "html": html,
        "css_list": css_list,
        "js_list": js_list
    }
