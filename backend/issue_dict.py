"""
Main scanning orchestrator.
Parses HTML/JS/CSS, analyzes each token, and stores issues based on ruleset.
"""
from html_scanner import scan_html
from js_scanner import scan_js
from css_scanner import scan_css


def run_scan(html, js_list, css_list, page_url=None):
    """
    Main scan function: parse -> analyze -> store results.
    
    Args:
        html: HTML content string
        js_list: List of JavaScript code strings
        css_list: List of CSS code strings
        page_url: Optional URL of the page
    
    Returns:
        dict with score, issues list, and issue_count
    """
    issues = []
    
    # Parse and analyze HTML
    issues.extend(scan_html(html, page_url=page_url))
    
    # Parse and analyze each JavaScript file
    for js_code in js_list:
        issues.extend(scan_js(js_code))
    
    # Parse and analyze each CSS file
    for css_code in css_list:
        issues.extend(scan_css(css_code))
    
    # Compute security score
    score = compute_score(issues)
    
    return {
        "score": score,
        "issues": issues,
        "issue_count": len(issues),
    }


def compute_score(issues):
    """
    Calculate security score based on issue severities.
    Starts at 100, deducts points for each issue.
    """
    score = 100
    
    for issue in issues:
        severity = issue.get("severity", "low")
        if severity == "low":
            score -= 2
        elif severity == "medium":
            score -= 5
        elif severity == "high":
            score -= 10
    
    return max(0, score)
