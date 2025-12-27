"""
JavaScript security scanner.

This module analyzes JavaScript code for security issues:
- Dangerous functions (eval, Function constructor, document.write)
- DOM injection patterns (innerHTML, outerHTML)
- Redirect handlers combined with click events
- Popup spam
- Crypto mining scripts
- Obfuscated/encoded JavaScript
- Autoplay media injection
- Cookie manipulation

All detection functions add issues to a shared list with severity and category.
"""
import re


def scan_js(js_code: str) -> list[dict]:
    """
    Main JS scanner entry point.
    """
    issues: list[dict] = []

    detect_eval_and_function(js_code, issues)
    detect_document_write(js_code, issues)
    detect_dom_injection_patterns(js_code, issues)
    detect_redirect_handlers(js_code, issues)
    detect_popup_spam(js_code, issues)
    detect_crypto_mining(js_code, issues)
    detect_obfuscation(js_code, issues)
    detect_autoplay_injection(js_code, issues)
    detect_cookie_manipulation(js_code, issues)

    return issues


# ------------- Classic dangerous functions -------------


def detect_eval_and_function(js: str, issues: list[dict]) -> None:
    if "eval(" in js:
        issues.append({
            "issue": "Use of eval() in JavaScript",
            "severity": "high",
            "category": "malicious_js",
        })

    # Dynamic Function constructor
    if "Function(" in js or "new Function(" in js:
        issues.append({
            "issue": "Use of Function constructor in JavaScript",
            "severity": "high",
            "category": "malicious_js",
        })


def detect_document_write(js: str, issues: list[dict]) -> None:
    if "document.write" in js:
        issues.append({
            "issue": "Use of document.write() can lead to injection",
            "severity": "low",
            "category": "malicious_js",
        })


def detect_dom_injection_patterns(js: str, issues: list[dict]) -> None:
    patterns = ["innerHTML", "outerHTML", "insertAdjacentHTML"]
    if any(p in js for p in patterns):
        issues.append({
            "issue": "Direct DOM HTML injection patterns detected",
            "severity": "medium",
            "category": "malicious_js",
        })


# ------------- Redirects, popups, click hijacking -------------


def detect_redirect_handlers(js: str, issues: list[dict]) -> None:
    redirect_keywords = [
        "window.location",
        "location.href",
        "location.assign",
        "location.replace",
        "window.open(",
    ]

    click_bindings = [
        "document.onclick",
        "document.onmousedown",
        "document.addEventListener('click'",
        'document.addEventListener("click"',
    ]

    if any(cb in js for cb in click_bindings) and any(rk in js for rk in redirect_keywords):
        issues.append({
            "issue": "Click handler that triggers redirect or new window",
            "severity": "high",
            "category": "malicious_js",
        })


def detect_popup_spam(js: str, issues: list[dict]) -> None:
    popup_patterns = [
        "window.open(",
        "openNewWindow(",
        "window.showModalDialog",
    ]

    if any(p in js for p in popup_patterns):
        issues.append({
            "issue": "Popup or new window behavior detected",
            "severity": "medium",
            "category": "malicious_js",
        })


# ------------- Crypto mining and obfuscation -------------


def detect_crypto_mining(js: str, issues: list[dict]) -> None:
    suspicious_terms = [
        "coinhive",
        "miner",
        "hashrate",
        "webmine",
    ]

    wasm_patterns = [
        "WebAssembly.instantiate",
        "WebAssembly.compile",
    ]

    if any(term in js for term in suspicious_terms) or any(wp in js for wp in wasm_patterns):
        issues.append({
            "issue": "Possible crypto mining script detected",
            "severity": "high",
            "category": "malicious_js",
        })


def detect_obfuscation(js: str, issues: list[dict]) -> None:
    # Only flag actual obfuscation, not minification or normal encoding
    # Look for very long hex strings (50+ bytes) - likely obfuscation
    long_hex = re.search(r"(?:\\x[0-9a-fA-F]{2}){50,}", js)
    # Very long base64 strings (100+ chars) - likely obfuscation
    long_base64 = re.search(r"[A-Za-z0-9+/]{100,}={0,2}", js)
    # Look for common obfuscation patterns
    obfuscation_patterns = [
        r"eval\s*\(\s*atob\s*\(",
        r"Function\s*\(\s*['\"][a-zA-Z0-9+/]{50,}",
        r"String\.fromCharCode\s*\([^)]{100,}\)",
    ]

    has_obfuscation = long_hex or long_base64 or any(re.search(p, js) for p in obfuscation_patterns)
    
    if has_obfuscation:
        issues.append({
            "issue": "Obfuscated or encoded JavaScript detected",
            "severity": "high",
            "category": "malicious_js",
        })


# ------------- Autoplay and media injection -------------


def detect_autoplay_injection(js: str, issues: list[dict]) -> None:
    media_patterns = [
        "new Audio(",
        ".play()",
        "HTMLAudioElement",
        "HTMLVideoElement",
    ]

    if "play()" in js and any(m in js for m in media_patterns):
        issues.append({
            "issue": "Possible auto play of media without user interaction",
            "severity": "medium",
            "category": "malicious_js",
        })


# ------------- Cookie and tracking manipulation -------------


def detect_cookie_manipulation(js: str, issues: list[dict]) -> None:
    if "document.cookie" in js:
        issues.append({
            "issue": "JavaScript manipulating document.cookie",
            "severity": "medium",
            "category": "tracking",
        })