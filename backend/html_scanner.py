# scanners/html_scanner.py

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
    detect_mixed_http(html, page_url, issues)
    detect_iframe_abuse(soup, issues)
    detect_hidden_elements(soup, issues)
    detect_offscreen_elements(soup, issues)
    detect_tiny_click_targets(soup, issues)
    detect_hidden_input_fields(soup, issues)
    detect_clickjacking_overlays(soup, issues)
    detect_fake_links_and_text(soup, issues)
    detect_fake_play_buttons(soup, issues)
    detect_meta_refresh_redirects(soup, issues)
    detect_fake_captcha_boxes(soup, issues)

    return issues


# ------------- Basic HTML security checks -------------


def detect_inline_js(soup: BeautifulSoup, issues: list[dict]) -> None:
    for script in soup.find_all("script"):
        if not script.get("src"):
            issues.append({
                "issue": "Inline JavaScript detected",
                "severity": "medium",
                "category": "malicious_js",
            })


def detect_deprecated_tags(soup: BeautifulSoup, issues: list[dict]) -> None:
    deprecated = ["font", "center", "marquee"]
    for tag_name in deprecated:
        for _ in soup.find_all(tag_name):
            issues.append({
                "issue": f"Deprecated <{tag_name}> tag found",
                "severity": "low",
                "category": "css_abuse",
            })


def detect_mixed_http(html: str, page_url: str | None, issues: list[dict]) -> None:
    # Simple mixed content check
    if "http://" in html:
        # If page itself is http, mixed content is less relevant
        if not page_url or page_url.startswith("https://"):
            issues.append({
                "issue": "Mixed content: insecure http references in page",
                "severity": "medium",
                "category": "redirect",
            })


# ------------- Iframe abuse -------------


def detect_iframe_abuse(soup: BeautifulSoup, issues: list[dict]) -> None:
    iframes = soup.find_all("iframe")
    count = len(iframes)
    if count == 0:
        return

    if count >= 3:
        issues.append({
            "issue": f"{count} iframes detected, possible ad or tracking nesting",
            "severity": "high",
            "category": "iframe_abuse",
        })
    else:
        issues.append({
            "issue": f"{count} iframes detected",
            "severity": "medium",
            "category": "iframe_abuse",
        })


# ------------- UI deception and hidden elements -------------


def _style_string(tag) -> str:
    style = tag.get("style", "")
    return style.replace(" ", "").lower()


def detect_hidden_elements(soup: BeautifulSoup, issues: list[dict]) -> None:
    hidden_markers = [
        "opacity:0",
        "display:none",
        "visibility:hidden",
    ]

    for tag in soup.find_all():
        style = _style_string(tag)
        if any(marker in style for marker in hidden_markers):
            issues.append({
                "issue": "Hidden DOM element via opacity/display/visibility",
                "severity": "medium",
                "category": "css_abuse",
            })


def detect_offscreen_elements(soup: BeautifulSoup, issues: list[dict]) -> None:
    offscreen_markers = [
        "-9999px",
        "left:-",
        "right:-",
        "top:-",
        "bottom:-",
    ]

    for tag in soup.find_all():
        style = _style_string(tag)
        if any(marker in style for marker in offscreen_markers):
            issues.append({
                "issue": "Offscreen positioned element (possible deceptive UI)",
                "severity": "medium",
                "category": "ui_deception",
            })


def detect_tiny_click_targets(soup: BeautifulSoup, issues: list[dict]) -> None:
    for a in soup.find_all("a"):
        style = _style_string(a)
        if "width:1px" in style or "height:1px" in style:
            issues.append({
                "issue": "Tiny click target anchor detected (phishing or tracking)",
                "severity": "medium",
                "category": "ui_deception",
            })


def detect_hidden_input_fields(soup: BeautifulSoup, issues: list[dict]) -> None:
    for inp in soup.find_all("input"):
        itype = (inp.get("type") or "").lower()
        if itype == "hidden":
            issues.append({
                "issue": "Hidden input field detected",
                "severity": "medium",
                "category": "tracking",
            })


def detect_clickjacking_overlays(soup: BeautifulSoup, issues: list[dict]) -> None:
    for tag in soup.find_all():
        style = _style_string(tag)

        has_full_screen_size = "width:100%" in style and "height:100%" in style
        is_positioned = "position:absolute" in style or "position:fixed" in style
        is_at_origin = "top:0" in style and "left:0" in style
        is_invisible = "opacity:0" in style or "visibility:hidden" in style

        if has_full_screen_size and is_positioned and is_at_origin and is_invisible:
            issues.append({
                "issue": "Full page invisible overlay detected (clickjacking risk)",
                "severity": "high",
                "category": "clickjacking",
            })


# ------------- Links and fake buttons -------------


def detect_fake_links_and_text(soup: BeautifulSoup, issues: list[dict]) -> None:
    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        text = a.get_text(strip=True)

        # Fake / no-op links
        if href in ("", "#", "javascript:void(0)", "javascript:;"):
            issues.append({
                "issue": "Fake link without real destination",
                "severity": "medium",
                "category": "ui_deception",
            })

        # Deceptive anchor text versus domain
        if href.startswith("http"):
            try:
                domain = urlparse(href).netloc.lower()
            except Exception:
                continue

            if text and domain and domain not in text.lower():
                issues.append({
                    "issue": f"Potential deceptive link text: '{text}' points to {domain}",
                    "severity": "medium",
                    "category": "redirect",
                })

            # Suspicious TLDs often used in streaming or ad networks
            suspicious_tlds = (".xyz", ".top", ".club", ".live", ".cc")
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                issues.append({
                    "issue": f"Link to suspicious domain {domain}",
                    "severity": "high",
                    "category": "redirect",
                })


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
                issues.append({
                    "issue": "Possible fake play button or overlay",
                    "severity": "medium",
                    "category": "ui_deception",
                })


# ------------- Meta refresh and fake captchas -------------


def detect_meta_refresh_redirects(soup: BeautifulSoup, issues: list[dict]) -> None:
    for meta in soup.find_all("meta"):
        http_equiv = (meta.get("http-equiv") or meta.get("http_equiv") or "").lower()
        content = (meta.get("content") or "").lower()

        if http_equiv == "refresh" and "url=" in content:
            issues.append({
                "issue": "Meta refresh redirect detected",
                "severity": "high",
                "category": "redirect",
            })


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
            issues.append({
                "issue": "Possible fake captcha box with no real verification",
                "severity": "high",
                "category": "ui_deception",
            })