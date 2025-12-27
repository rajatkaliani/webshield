"""
HTML security scanner.

This module analyzes HTML content for security issues:
- Inline JavaScript with suspicious patterns (eval, Function, etc.)
- Deprecated HTML tags
- Mixed HTTP/HTTPS content
- Iframe abuse (multiple iframes)
- Hidden/offscreen clickable elements (UI deception)
- Fake/deceptive links
- Clickjacking overlays
- Meta refresh redirects
- Fake captcha boxes

All detection functions add issues to a shared list with severity and category.
"""
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def scan_html(html: str, page_url: str | None = None) -> list[dict]:
    """
    Main HTML scanner entry point.
    """
    issues: list[dict] = []
    soup = BeautifulSoup(html, "html.parser")

    detect_inline_js(soup, issues)
    detect_deprecated_tags(soup, issues)
    detect_insecure_http(page_url, issues)
    detect_mixed_http(html, page_url, issues)
    detect_iframe_abuse(soup, issues)
    detect_hidden_elements(soup, issues)
    detect_offscreen_elements(soup, issues)
    detect_tiny_click_targets(soup, issues)
    detect_hidden_input_fields(soup, issues)
    detect_clickjacking_overlays(soup, issues)
    detect_overlayed_links(soup, issues)
    detect_fake_links_and_text(soup, issues, page_url)
    detect_fake_play_buttons(soup, issues)
    detect_meta_refresh_redirects(soup, issues)
    detect_fake_captcha_boxes(soup, issues)

    return issues


# ------------- Basic HTML security checks -------------


def detect_inline_js(soup: BeautifulSoup, issues: list[dict]) -> None:
    # Only flag inline JS if it contains suspicious patterns
    suspicious_patterns = ["eval(", "Function(", "document.write", "innerHTML", "atob(", "fromCharCode"]
    
    for script in soup.find_all("script"):
        if not script.get("src"):
            script_content = script.string or ""
            if any(pattern in script_content for pattern in suspicious_patterns):
                selector = _get_element_selector(script)
                _add_issue(issues, "Inline JavaScript with suspicious patterns detected", "medium", "malicious_js", selector)


def detect_deprecated_tags(soup: BeautifulSoup, issues: list[dict]) -> None:
    deprecated = ["font", "center", "marquee"]
    for tag_name in deprecated:
        for tag in soup.find_all(tag_name):
            selector = _get_element_selector(tag)
            _add_issue(issues, f"Deprecated <{tag_name}> tag found", "low", "css_abuse", selector)


def detect_insecure_http(page_url: str | None, issues: list[dict]) -> None:
    """Detect if page is served over HTTP instead of HTTPS."""
    if page_url and page_url.startswith("http://"):
        _add_issue(issues, "Page served over insecure HTTP instead of HTTPS", "high", "redirect")


def detect_mixed_http(html: str, page_url: str | None, issues: list[dict]) -> None:
    # Only flag if actually loading resources over HTTP (not just mentions in comments/text)
    import re
    # Look for actual resource loading: src="http://", href="http://", url(http://
    resource_patterns = [
        r'src=["\']http://',
        r'href=["\']http://',
        r'url\(http://',
        r'@import\s+["\']?http://'
    ]
    
    if not page_url or page_url.startswith("https://"):
        for pattern in resource_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                issues.append({
                    "issue": "Mixed content: insecure http resources detected",
                    "severity": "medium",
                    "category": "redirect",
                })
                break  # Only report once


# ------------- Iframe abuse -------------


def detect_iframe_abuse(soup: BeautifulSoup, issues: list[dict]) -> None:
    iframes = soup.find_all("iframe")
    count = len(iframes)
    if count == 0:
        return

    # For iframes, we'll highlight all of them
    iframe_selectors = [_get_element_selector(iframe) for iframe in iframes[:5]]  # Limit to first 5
    if count >= 3:
        _add_issue(issues, f"{count} iframes detected, possible ad or tracking nesting", "high", "iframe_abuse", ",".join(iframe_selectors))
    else:
        _add_issue(issues, f"{count} iframes detected", "medium", "iframe_abuse", ",".join(iframe_selectors))


# ------------- UI deception and hidden elements -------------


def _style_string(tag) -> str:
    """Normalize style attribute for pattern matching."""
    return tag.get("style", "").replace(" ", "").lower()


def _is_clickable(tag) -> bool:
    """Check if element is clickable."""
    return tag.name in ["a", "button", "input"] or tag.get("onclick") or tag.get("href")


def _add_issue(issues, issue_text, severity, category, element_selector=None):
    """Helper to add issue to list with optional element selector for highlighting."""
    issue = {"issue": issue_text, "severity": severity, "category": category}
    if element_selector:
        issue["element_selector"] = element_selector
    issues.append(issue)


def _get_element_selector(tag):
    """Generate a CSS selector for an element to enable highlighting."""
    # Build selector from tag name, id, classes
    selector = tag.name
    
    # Add ID if present
    if tag.get("id"):
        selector += f"#{tag.get('id')}"
    
    # Add classes if present
    classes = tag.get("class", [])
    if classes:
        if isinstance(classes, list):
            class_str = ".".join(classes)
        else:
            class_str = classes
        selector += f".{class_str.replace(' ', '.')}"
    
    # Add nth-of-type if needed for uniqueness
    if not tag.get("id") and not classes:
        parent = tag.parent
        if parent:
            siblings = [s for s in parent.children if hasattr(s, 'name') and s.name == tag.name]
            if len(siblings) > 1:
                index = siblings.index(tag) + 1
                selector += f":nth-of-type({index})"
    
    return selector


def detect_hidden_elements(soup: BeautifulSoup, issues: list[dict]) -> None:
    # Only flag if hidden element is clickable or has suspicious attributes
    hidden_markers = [
        "opacity:0",
        "display:none",
        "visibility:hidden",
    ]

    for tag in soup.find_all():
        style = _style_string(tag)
        if any(marker in style for marker in hidden_markers):
            if _is_clickable(tag):
                selector = _get_element_selector(tag)
                _add_issue(issues, "Hidden clickable element detected (possible UI deception)", "medium", "css_abuse", selector)


def detect_offscreen_elements(soup: BeautifulSoup, issues: list[dict]) -> None:
    # Only flag if element is positioned way offscreen (screen reader technique uses -9999px legitimately)
    # Only flag if it's a clickable element positioned offscreen
    offscreen_markers = [
        "left:-9999px",
        "right:-9999px",
        "top:-9999px",
        "bottom:-9999px",
    ]

    for tag in soup.find_all():
        style = _style_string(tag)
        if any(marker in style for marker in offscreen_markers) and _is_clickable(tag):
            selector = _get_element_selector(tag)
            _add_issue(issues, "Offscreen clickable element detected (possible deceptive UI)", "medium", "ui_deception", selector)


def detect_tiny_click_targets(soup: BeautifulSoup, issues: list[dict]) -> None:
    # Only check actual links (with href), not anchor points
    for a in soup.find_all("a", href=True):
        style = _style_string(a)
        if "width:1px" in style or "height:1px" in style:
            selector = _get_element_selector(a)
            _add_issue(issues, "Tiny click target anchor detected (phishing or tracking)", "medium", "ui_deception", selector)


def detect_hidden_input_fields(soup: BeautifulSoup, issues: list[dict]) -> None:
    for inp in soup.find_all("input"):
        itype = (inp.get("type") or "").lower()
        if itype == "hidden":
            selector = _get_element_selector(inp)
            _add_issue(issues, "Hidden input field detected", "medium", "tracking", selector)


def detect_clickjacking_overlays(soup: BeautifulSoup, issues: list[dict]) -> None:
    """Detect full-page invisible overlays (clickjacking)."""
    for tag in soup.find_all():
        style = _style_string(tag)

        has_full_screen_size = "width:100%" in style and "height:100%" in style
        is_positioned = "position:absolute" in style or "position:fixed" in style
        is_at_origin = "top:0" in style and "left:0" in style
        is_invisible = "opacity:0" in style or "visibility:hidden" in style

        if has_full_screen_size and is_positioned and is_at_origin and is_invisible:
            selector = _get_element_selector(tag)
            _add_issue(issues, "Full page invisible overlay detected (clickjacking risk)", "high", "clickjacking", selector)


def detect_overlayed_links(soup: BeautifulSoup, issues: list[dict]) -> None:
    """
    Detect elements positioned over links to intercept clicks.
    
    This checks for suspicious patterns where positioned elements
    might be overlaying clickable links.
    """
    # Find all links
    links = soup.find_all("a", href=True)
    
    for link in links:
        link_style = _style_string(link)
        
        # Check if link has positioning (might be overlayed)
        if "position:relative" in link_style or "position:absolute" in link_style:
            # Look for siblings or nearby elements that might overlay it
            parent = link.parent
            if parent:
                siblings = [s for s in parent.children if hasattr(s, 'name') and s.name]
                
                for sibling in siblings:
                    if sibling == link:
                        continue
                    
                    sibling_style = _style_string(sibling)
                    
                    # Check if sibling is positioned and might overlay the link
                    is_positioned_overlay = (
                        ("position:absolute" in sibling_style or "position:fixed" in sibling_style) and
                        ("z-index" in sibling_style or "opacity" in sibling_style)
                    )
                    
                    # Check if it's clickable (div, span with onclick, etc.)
                    is_clickable_overlay = (
                        sibling.name in ["div", "span", "button"] and
                        (sibling.get("onclick") or sibling.get("href") or _is_clickable(sibling))
                    )
                    
                    if is_positioned_overlay and is_clickable_overlay:
                        # Check if it's invisible or semi-transparent (suspicious)
                        is_invisible = "opacity:0" in sibling_style or "opacity:0." in sibling_style or "visibility:hidden" in sibling_style
                        
                        if is_invisible:
                            selector = _get_element_selector(sibling)
                            _add_issue(issues, "Invisible element positioned over link (possible click interception)", "high", "clickjacking", selector)
                        elif "z-index" in sibling_style:
                            # High z-index over link is suspicious
                            selector = _get_element_selector(sibling)
                            _add_issue(issues, "Element with high z-index positioned over link (possible overlay attack)", "medium", "ui_deception", selector)


# ------------- Links and fake buttons -------------


def detect_fake_links_and_text(soup: BeautifulSoup, issues: list[dict], page_url: str | None = None) -> None:
    # Only check anchors that have an href attribute (actual links, not anchor points)
    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        text = a.get_text(strip=True)

        # Skip legitimate link patterns
        # "#" links scroll to anchors (legitimate - don't flag)
        # "javascript:void(0)" and similar are used for JS actions (legitimate - don't flag)
        # Relative paths like "/page" or "page.html" are legitimate (don't flag)
        # Only flag truly empty href (not "#", not "javascript:", not relative paths)
        if href == "" and not a.get("onclick"):
            # Check if it has any other interaction (data attributes, role, etc.)
            has_interaction = (
                a.get("role") == "button" or 
                a.get("data-toggle") or 
                a.get("data-target") or
                a.get("data-action") or
                a.get("aria-label")  # Often used for accessible buttons
            )
            if not has_interaction:
                selector = _get_element_selector(a)
                _add_issue(issues, "Link with empty href and no interaction handler", "low", "ui_deception", selector)

        # Only flag links with suspicious TLDs (these are actually suspicious)
        # We don't flag "deceptive" links based on text vs domain - that's too subjective
        # and legitimate sites often have links like "Click here" pointing to different domains
        if href.startswith("http"):
            try:
                domain = urlparse(href).netloc.lower()
            except Exception:
                continue

            # Legitimate TLDs (com, edu, org, net, gov, etc. are all fine)
            legitimate_tlds = (".com", ".edu", ".org", ".net", ".gov", ".mil", ".io", ".co", 
                              ".uk", ".ca", ".au", ".de", ".fr", ".jp", ".cn", ".in", ".br",
                              ".us", ".info", ".biz", ".name", ".pro", ".tv", ".me", ".app")
            
            # Only flag if it's NOT a legitimate TLD and matches suspicious patterns
            is_legitimate = any(domain.endswith(tld) for tld in legitimate_tlds)
            
            if not is_legitimate:
                # Suspicious TLDs often used in streaming, ad networks, or malicious sites
                suspicious_tlds = (".xyz", ".top", ".club", ".live", ".cc", ".tk", ".ml", ".ga", ".cf")
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    selector = _get_element_selector(a)
                    _add_issue(issues, f"Link to suspicious TLD domain: {domain}", "high", "redirect", selector)


def detect_fake_play_buttons(soup: BeautifulSoup, issues: list[dict]) -> None:
    # Simple heuristics for fake play overlays
    play_keywords = ("play", "watch", "stream")

    for tag in soup.find_all(["a", "button", "div", "span", "img"]):
        text = tag.get_text(strip=True).lower()
        classes = " ".join(tag.get("class", [])).lower()
        alt = (tag.get("alt") or "").lower()
        style = _style_string(tag)

        combined = " ".join([text, classes, alt])

        if any(kw in combined for kw in play_keywords):
            # suspicious if it is absolutely positioned on top
            if "position:absolute" in style or "position:fixed" in style:
                selector = _get_element_selector(tag)
                _add_issue(issues, "Possible fake play button or overlay", "medium", "ui_deception", selector)


# ------------- Meta refresh and fake captchas -------------


def detect_meta_refresh_redirects(soup: BeautifulSoup, issues: list[dict]) -> None:
    for meta in soup.find_all("meta"):
        http_equiv = (meta.get("http-equiv") or meta.get("http_equiv") or "").lower()
        content = (meta.get("content") or "").lower()

        if http_equiv == "refresh" and "url=" in content:
            selector = _get_element_selector(meta)
            _add_issue(issues, "Meta refresh redirect detected", "high", "redirect", selector)


def detect_fake_captcha_boxes(soup: BeautifulSoup, issues: list[dict]) -> None:
    # Very heuristic based: boxes that look like captcha but no known provider
    captcha_like = []

    for div in soup.find_all("div"):
        classes = " ".join(div.get("class", [])).lower()
        text = div.get_text(strip=True).lower()

        if "captcha" in classes or "captcha" in text:
            captcha_like.append(div)

    for box in captcha_like:
        # Check if page includes real reCAPTCHA or hcaptcha script
        scripts = [s.get("src", "") for s in box.find_all("script")]
        has_real_captcha = any(
            "google.com/recaptcha" in src or "hcaptcha.com" in src for src in scripts
        )

        if not has_real_captcha:
            selector = _get_element_selector(box)
            _add_issue(issues, "Possible fake captcha box with no real verification", "high", "ui_deception", selector)