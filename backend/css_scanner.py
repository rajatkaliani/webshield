"""
CSS security scanner.

This module analyzes CSS code for security issues:
- Excessive hidden elements (opacity, display, visibility)
- Offscreen positioning (UI deception)
- Very large z-index values (overlay abuse)
- Pointer-events manipulation
- Tiny clickable areas (1px targets)
- CSS expression() usage (old IE scripting)
- Excessive !important usage

All detection functions add issues to a shared list with severity and category.
Thresholds are set to avoid false positives on legitimate sites.
"""
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
    # Only flag if there are many hidden rules (suspicious pattern)
    # A few hidden elements are normal for UI (modals, dropdowns, etc.)
    markers = [
        "opacity: 0",
        "opacity:0",
        "display: none",
        "display:none",
        "visibility: hidden",
        "visibility:hidden",
    ]
    count = sum(css.count(m) for m in markers)
    # Only flag if there are 20+ hidden rules (excessive)
    if count >= 20:
        issues.append({
            "issue": f"Excessive hidden CSS rules detected ({count} instances)",
            "severity": "low",
            "category": "css_abuse",
        })


def detect_offscreen_rules(css: str, issues: list[dict]) -> None:
    # Only flag if positioned way offscreen (screen reader technique uses -9999px legitimately)
    # Only flag if excessive (10+ instances of extreme offscreen positioning)
    extreme_pattern = r"(left|right|top|bottom)\s*:\s*-[5-9]\d{3,}px"
    matches = re.findall(extreme_pattern, css)
    if len(matches) >= 10:
        issues.append({
            "issue": f"Excessive extreme offscreen positioning detected ({len(matches)} instances)",
            "severity": "low",
            "category": "ui_deception",
        })


def detect_zindex_abuse(css: str, issues: list[dict]) -> None:
    # Only flag if there are many very large z-index values (excessive)
    matches = re.findall(r"z-index\s*:\s*(9999|99999|999999)", css)
    if len(matches) >= 10:
        issues.append({
            "issue": f"Excessive large z-index values detected ({len(matches)} instances)",
            "severity": "low",
            "category": "css_abuse",
        })


def detect_pointer_events_tricks(css: str, issues: list[dict]) -> None:
    # Only flag if excessive use (pointer-events: none is legitimate for many UI patterns)
    count = css.count("pointer-events: none") + css.count("pointer-events:none")
    if count >= 20:
        issues.append({
            "issue": f"Excessive pointer-events manipulation detected ({count} instances)",
            "severity": "low",
            "category": "ui_deception",
        })


def detect_tiny_click_targets(css: str, issues: list[dict]) -> None:
    # Only flag if there are many tiny targets (1px is sometimes used for screen readers)
    tiny_width = len(re.findall(r"width\s*:\s*1px", css))
    tiny_height = len(re.findall(r"height\s*:\s*1px", css))
    total = tiny_width + tiny_height
    
    if total >= 5:
        issues.append({
            "issue": f"Multiple tiny clickable areas detected ({total} instances)",
            "severity": "low",
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
    # Increase threshold - large sites legitimately use many !important
    count = css.count("!important")
    if count >= 200:
        issues.append({
            "issue": f"Excessive use of !important ({count} times)",
            "severity": "low",
            "category": "css_abuse",
        })