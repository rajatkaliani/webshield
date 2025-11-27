# scanners/js_scanner.py

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
    # Heuristics for obfuscated payloads: long base64 or hex strings
    long_hex = re.search(r"(?:\\x[0-9a-fA-F]{2}){8,}", js)
    long_base64 = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", js)

    if long_hex or long_base64:
        issues.append({
            "issue": "Obfuscated or encoded JavaScript detected",
            "severity": "high",
            "category": "malicious_js",
        })

    # Single-letter variable patterns repeated
    if re.search(r"var\s+[a-zA-Z]\s*=", js) and js.count("var ") > 10:
        issues.append({
            "issue": "Heavily minified or obfuscated variable naming pattern",
            "severity": "medium",
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