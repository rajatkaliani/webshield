"""
Main scanning orchestrator.

This module coordinates the security scanning process:
1. Runs HTML, JavaScript, and CSS scanners
2. Collects all security issues found
3. Calculates a security score (starts at 100, deducts points per issue)
4. Returns results with score, issues list, and issue count

Scoring: Low = -2, Medium = -5, High = -10 points
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
    
    # Scan HTML
    issues.extend(scan_html(html, page_url=page_url))
    
    # Scan each JavaScript file
    for js_code in js_list:
        issues.extend(scan_js(js_code))
    
    # Scan each CSS file
    for css_code in css_list:
        issues.extend(scan_css(css_code))
    
    # Calculate security score
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
    Minimum score is 0.
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
