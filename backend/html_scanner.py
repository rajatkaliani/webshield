"""
HTML Scanner: Parse HTML, analyze each element, store issues based on rules.
"""
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def scan_html(html, page_url=None):
    """
    Parse HTML and analyze each element against security rules.
    
    Returns list of issues found.
    """
    issues = []
    soup = BeautifulSoup(html, "html.parser")
    
    # Analyze each element type
    analyze_scripts(soup, issues)
    analyze_tags(soup, issues)
    analyze_links(soup, issues)
    analyze_iframes(soup, issues)
    analyze_inputs(soup, issues)
    analyze_styles(soup, issues)
    analyze_meta_tags(soup, issues)
    analyze_content(html, page_url, issues)
    
    return issues


# ==================== Analysis Functions ====================

def analyze_scripts(soup, issues):
    """Analyze script tags for inline JavaScript."""
    for script in soup.find_all("script"):
        if not script.get("src"):
            store_issue(issues, "Inline JavaScript detected", "medium", "malicious_js")


def analyze_tags(soup, issues):
    """Analyze HTML tags for deprecated or suspicious patterns."""
    # Deprecated tags
    deprecated = ["font", "center", "marquee"]
    for tag_name in deprecated:
        if soup.find_all(tag_name):
            store_issue(issues, f"Deprecated <{tag_name}> tag found", "low", "css_abuse")
    
    # Hidden elements
    for tag in soup.find_all():
        style = get_style_string(tag)
        if has_hidden_style(style):
            store_issue(issues, "Hidden DOM element detected", "medium", "css_abuse")
    
    # Offscreen elements
    for tag in soup.find_all():
        style = get_style_string(tag)
        if has_offscreen_style(style):
            store_issue(issues, "Offscreen positioned element (possible deceptive UI)", "medium", "ui_deception")
    
    # Clickjacking overlays
    for tag in soup.find_all():
        style = get_style_string(tag)
        if is_clickjacking_overlay(style):
            store_issue(issues, "Full page invisible overlay detected (clickjacking risk)", "high", "clickjacking")


def analyze_links(soup, issues):
    """Analyze anchor tags for fake or deceptive links."""
    for link in soup.find_all("a"):
        href = (link.get("href") or "").strip()
        text = link.get_text(strip=True)
        style = get_style_string(link)
        
        # Fake links
        if href in ("", "#", "javascript:void(0)", "javascript:;"):
            store_issue(issues, "Fake link without real destination", "medium", "ui_deception")
        
        # Tiny click targets
        if "width:1px" in style or "height:1px" in style:
            store_issue(issues, "Tiny click target anchor detected", "medium", "ui_deception")
        
        # Deceptive link text
        if href.startswith("http"):
            try:
                domain = urlparse(href).netloc.lower()
                if text and domain and domain not in text.lower():
                    store_issue(issues, f"Potential deceptive link: '{text}' points to {domain}", "medium", "redirect")
                
                # Suspicious TLDs
                suspicious_tlds = (".xyz", ".top", ".club", ".live", ".cc")
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    store_issue(issues, f"Link to suspicious domain {domain}", "high", "redirect")
            except:
                pass


def analyze_iframes(soup, issues):
    """Analyze iframe tags for abuse."""
    iframes = soup.find_all("iframe")
    count = len(iframes)
    
    if count == 0:
        return
    
    if count >= 3:
        store_issue(issues, f"{count} iframes detected, possible ad or tracking nesting", "high", "iframe_abuse")
    else:
        store_issue(issues, f"{count} iframes detected", "medium", "iframe_abuse")


def analyze_inputs(soup, issues):
    """Analyze input fields for hidden or suspicious patterns."""
    for inp in soup.find_all("input"):
        input_type = (inp.get("type") or "").lower()
        if input_type == "hidden":
            store_issue(issues, "Hidden input field detected", "medium", "tracking")


def analyze_styles(soup, issues):
    """Analyze elements for fake play buttons or deceptive styling."""
    play_keywords = ("play", "watch", "stream")
    
    for tag in soup.find_all(["a", "button", "div", "span", "img"]):
        text = tag.get_text(strip=True).lower()
        classes = " ".join(tag.get("class", [])).lower()
        alt = (tag.get("alt") or "").lower()
        style = get_style_string(tag)
        
        combined = " ".join([text, classes, alt])
        
        if any(kw in combined for kw in play_keywords):
            if "position:absolute" in style or "position:fixed" in style:
                store_issue(issues, "Possible fake play button or overlay", "medium", "ui_deception")


def analyze_meta_tags(soup, issues):
    """Analyze meta tags for redirects and fake captchas."""
    # Meta refresh redirects
    for meta in soup.find_all("meta"):
        http_equiv = (meta.get("http-equiv") or meta.get("http_equiv") or "").lower()
        content = (meta.get("content") or "").lower()
        
        if http_equiv == "refresh" and "url=" in content:
            store_issue(issues, "Meta refresh redirect detected", "high", "redirect")
    
    # Fake captcha boxes
    for div in soup.find_all("div"):
        classes = " ".join(div.get("class", [])).lower()
        text = div.get_text(strip=True).lower()
        
        if "captcha" in classes or "captcha" in text:
            scripts = [s.get("src", "") for s in div.find_all("script")]
            has_real_captcha = any(
                "google.com/recaptcha" in src or "hcaptcha.com" in src for src in scripts
            )
            
            if not has_real_captcha:
                store_issue(issues, "Possible fake captcha box with no real verification", "high", "ui_deception")


def analyze_content(html, page_url, issues):
    """Analyze HTML content for mixed HTTP/HTTPS."""
    if "http://" in html:
        if not page_url or page_url.startswith("https://"):
            store_issue(issues, "Mixed content: insecure http references in page", "medium", "redirect")


# ==================== Helper Functions ====================

def get_style_string(tag):
    """Extract and normalize style attribute."""
    style = tag.get("style", "")
    return style.replace(" ", "").lower()


def has_hidden_style(style):
    """Check if style hides element."""
    hidden_markers = ["opacity:0", "display:none", "visibility:hidden"]
    return any(marker in style for marker in hidden_markers)


def has_offscreen_style(style):
    """Check if style positions element offscreen."""
    offscreen_markers = ["-9999px", "left:-", "right:-", "top:-", "bottom:-"]
    return any(marker in style for marker in offscreen_markers)


def is_clickjacking_overlay(style):
    """Check if style creates clickjacking overlay."""
    has_full_screen = "width:100%" in style and "height:100%" in style
    is_positioned = "position:absolute" in style or "position:fixed" in style
    is_at_origin = "top:0" in style and "left:0" in style
    is_invisible = "opacity:0" in style or "visibility:hidden" in style
    
    return has_full_screen and is_positioned and is_at_origin and is_invisible


def store_issue(issues, issue_text, severity, category):
    """Store an issue in the issues list."""
    issues.append({
        "issue": issue_text,
        "severity": severity,
        "category": category,
    })
