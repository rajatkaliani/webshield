# scanners/css_scanner.py

import re


def scan_css(css_code: str) -> list[dict]:
    """
    Main CSS scanner entry point.
    """
    issues: list[dict] = []

    detect_hidden_rules(css_code, issues)
    detect_offscreen_rules(css_code, issues)
    detect_zindex_abuse(css_code, issues)
    detect_pointer_events_tricks(css_code, issues)
    detect_tiny_click_targets(css_code, issues)
    detect_expression_usage(css_code, issues)
    detect_excessive_important(css_code, issues)

    return issues


def detect_hidden_rules(css: str, issues: list[dict]) -> None:
    markers = [
        "opacity: 0",
        "opacity:0",
        "display: none",
        "display:none",
        "visibility: hidden",
        "visibility:hidden",
    ]
    if any(m in css for m in markers):
        issues.append({
            "issue": "CSS rules hide elements via opacity or display or visibility",
            "severity": "medium",
            "category": "css_abuse",
        })


def detect_offscreen_rules(css: str, issues: list[dict]) -> None:
    if re.search(r"(left|right|top|bottom)\s*:\s*-\d+px", css):
        issues.append({
            "issue": "CSS positions elements offscreen with negative coordinates",
            "severity": "medium",
            "category": "ui_deception",
        })


def detect_zindex_abuse(css: str, issues: list[dict]) -> None:
    # Very large z-index is often used for overlays
    if re.search(r"z-index\s*:\s*(9999|99999|999999)", css):
        issues.append({
            "issue": "Very large z-index values used (possible overlay or ad layer)",
            "severity": "medium",
            "category": "css_abuse",
        })


def detect_pointer_events_tricks(css: str, issues: list[dict]) -> None:
    if "pointer-events: none" in css or "pointer-events:none" in css:
        issues.append({
            "issue": "pointer-events none used to block or reroute clicks",
            "severity": "medium",
            "category": "ui_deception",
        })


def detect_tiny_click_targets(css: str, issues: list[dict]) -> None:
    # Look for width:1px / height:1px patterns
    tiny_width = re.search(r"width\s*:\s*1px", css)
    tiny_height = re.search(r"height\s*:\s*1px", css)

    if tiny_width or tiny_height:
        issues.append({
            "issue": "CSS defines tiny clickable areas (1px targets)",
            "severity": "medium",
            "category": "ui_deception",
        })


def detect_expression_usage(css: str, issues: list[dict]) -> None:
    if "expression(" in css:
        issues.append({
            "issue": "CSS expression() used (old IE scripting in CSS)",
            "severity": "high",
            "category": "css_abuse",
        })


def detect_excessive_important(css: str, issues: list[dict]) -> None:
    count = css.count("!important")
    if count >= 5:
        issues.append({
            "issue": f"Excessive use of !important ({count} times)",
            "severity": "low",
            "category": "css_abuse",
        })