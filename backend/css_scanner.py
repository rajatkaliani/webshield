"""
CSS Scanner: Parse CSS code, analyze each rule, store issues based on ruleset.
"""
import re


def scan_css(css_code):
    """
    Parse CSS code and analyze against security rules.
    
    Returns list of issues found.
    """
    issues = []
    
    # Analyze different CSS patterns
    analyze_hidden_rules(css_code, issues)
    analyze_offscreen_rules(css_code, issues)
    analyze_zindex_abuse(css_code, issues)
    analyze_pointer_events(css_code, issues)
    analyze_tiny_targets(css_code, issues)
    analyze_expressions(css_code, issues)
    analyze_important_usage(css_code, issues)
    
    return issues


# ==================== Analysis Functions ====================

def analyze_hidden_rules(css_code, issues):
    """Analyze for CSS rules that hide elements."""
    hidden_markers = [
        "opacity: 0",
        "opacity:0",
        "display: none",
        "display:none",
        "visibility: hidden",
        "visibility:hidden",
    ]
    
    if any(marker in css_code for marker in hidden_markers):
        store_issue(issues, "CSS rules hide elements via opacity or display or visibility", "medium", "css_abuse")


def analyze_offscreen_rules(css_code, issues):
    """Analyze for CSS rules that position elements offscreen."""
    if re.search(r"(left|right|top|bottom)\s*:\s*-\d+px", css_code):
        store_issue(issues, "CSS positions elements offscreen with negative coordinates", "medium", "ui_deception")


def analyze_zindex_abuse(css_code, issues):
    """Analyze for very large z-index values."""
    if re.search(r"z-index\s*:\s*(9999|99999|999999)", css_code):
        store_issue(issues, "Very large z-index values used (possible overlay or ad layer)", "medium", "css_abuse")


def analyze_pointer_events(css_code, issues):
    """Analyze for pointer-events manipulation."""
    if "pointer-events: none" in css_code or "pointer-events:none" in css_code:
        store_issue(issues, "pointer-events none used to block or reroute clicks", "medium", "ui_deception")


def analyze_tiny_targets(css_code, issues):
    """Analyze for tiny clickable areas."""
    tiny_width = re.search(r"width\s*:\s*1px", css_code)
    tiny_height = re.search(r"height\s*:\s*1px", css_code)
    
    if tiny_width or tiny_height:
        store_issue(issues, "CSS defines tiny clickable areas (1px targets)", "medium", "ui_deception")


def analyze_expressions(css_code, issues):
    """Analyze for CSS expression() usage."""
    if "expression(" in css_code:
        store_issue(issues, "CSS expression() used (old IE scripting in CSS)", "high", "css_abuse")


def analyze_important_usage(css_code, issues):
    """Analyze for excessive !important usage."""
    count = css_code.count("!important")
    if count >= 5:
        store_issue(issues, f"Excessive use of !important ({count} times)", "low", "css_abuse")


# ==================== Helper Functions ====================

def store_issue(issues, issue_text, severity, category):
    """Store an issue in the issues list."""
    issues.append({
        "issue": issue_text,
        "severity": severity,
        "category": category,
    })
