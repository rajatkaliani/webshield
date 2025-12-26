"""
JavaScript Scanner: Parse JS code, analyze each pattern, store issues based on rules.
"""
import re


def scan_js(js_code):
    """
    Parse JavaScript code and analyze against security rules.
    
    Returns list of issues found.
    """
    issues = []
    
    # Analyze different patterns
    analyze_dangerous_functions(js_code, issues)
    analyze_dom_injection(js_code, issues)
    analyze_redirects(js_code, issues)
    analyze_popups(js_code, issues)
    analyze_crypto_mining(js_code, issues)
    analyze_obfuscation(js_code, issues)
    analyze_autoplay(js_code, issues)
    analyze_cookies(js_code, issues)
    
    return issues


# ==================== Analysis Functions ====================

def analyze_dangerous_functions(js_code, issues):
    """Analyze for eval() and Function() constructor."""
    if "eval(" in js_code:
        store_issue(issues, "Use of eval() in JavaScript", "high", "malicious_js")
    
    if "Function(" in js_code or "new Function(" in js_code:
        store_issue(issues, "Use of Function constructor in JavaScript", "high", "malicious_js")
    
    if "document.write" in js_code:
        store_issue(issues, "Use of document.write() can lead to injection", "low", "malicious_js")


def analyze_dom_injection(js_code, issues):
    """Analyze for DOM HTML injection patterns."""
    patterns = ["innerHTML", "outerHTML", "insertAdjacentHTML"]
    if any(pattern in js_code for pattern in patterns):
        store_issue(issues, "Direct DOM HTML injection patterns detected", "medium", "malicious_js")


def analyze_redirects(js_code, issues):
    """Analyze for redirect handlers combined with click events."""
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
    
    has_click = any(cb in js_code for cb in click_bindings)
    has_redirect = any(rk in js_code for rk in redirect_keywords)
    
    if has_click and has_redirect:
        store_issue(issues, "Click handler that triggers redirect or new window", "high", "malicious_js")


def analyze_popups(js_code, issues):
    """Analyze for popup or new window behavior."""
    popup_patterns = [
        "window.open(",
        "openNewWindow(",
        "window.showModalDialog",
    ]
    
    if any(pattern in js_code for pattern in popup_patterns):
        store_issue(issues, "Popup or new window behavior detected", "medium", "malicious_js")


def analyze_crypto_mining(js_code, issues):
    """Analyze for crypto mining scripts."""
    suspicious_terms = ["coinhive", "miner", "hashrate", "webmine"]
    wasm_patterns = ["WebAssembly.instantiate", "WebAssembly.compile"]
    
    has_suspicious = any(term in js_code for term in suspicious_terms)
    has_wasm = any(wp in js_code for wp in wasm_patterns)
    
    if has_suspicious or has_wasm:
        store_issue(issues, "Possible crypto mining script detected", "high", "malicious_js")


def analyze_obfuscation(js_code, issues):
    """Analyze for obfuscated or encoded JavaScript."""
    # Long hex strings
    long_hex = re.search(r"(?:\\x[0-9a-fA-F]{2}){8,}", js_code)
    # Long base64 strings
    long_base64 = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", js_code)
    
    if long_hex or long_base64:
        store_issue(issues, "Obfuscated or encoded JavaScript detected", "high", "malicious_js")
    
    # Heavily minified pattern
    if re.search(r"var\s+[a-zA-Z]\s*=", js_code) and js_code.count("var ") > 10:
        store_issue(issues, "Heavily minified or obfuscated variable naming pattern", "medium", "malicious_js")


def analyze_autoplay(js_code, issues):
    """Analyze for autoplay media injection."""
    media_patterns = ["new Audio(", ".play()", "HTMLAudioElement", "HTMLVideoElement"]
    
    if "play()" in js_code and any(m in js_code for m in media_patterns):
        store_issue(issues, "Possible auto play of media without user interaction", "medium", "malicious_js")


def analyze_cookies(js_code, issues):
    """Analyze for cookie manipulation."""
    if "document.cookie" in js_code:
        store_issue(issues, "JavaScript manipulating document.cookie", "medium", "tracking")


# ==================== Helper Functions ====================

def store_issue(issues, issue_text, severity, category):
    """Store an issue in the issues list."""
    issues.append({
        "issue": issue_text,
        "severity": severity,
        "category": category,
    })
