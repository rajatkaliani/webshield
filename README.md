🛡️ WebShield

WebShield is a real-time web security analysis system built as a Chrome extension + FastAPI backend. It performs static analysis on live web pages by inspecting raw HTML, CSS, JavaScript, and the rendered DOM to detect deceptive UX patterns, dark patterns, and malicious client-side behaviors.

Unlike traditional malware scanners, WebShield targets non-obvious, adversarial web threats that rely on UI manipulation and subtle script-based behaviors rather than explicit exploits. The system produces a deterministic, explainable security score with categorized findings and visual DOM annotations.

🎥 Demo

▶️ Watch the demo:
https://youtu.be/4--ddW2lfLc

🚨 Why WebShield?

Modern web threats increasingly hide behind interface design, not malware.

Misleading links, false affordances, invisible overlays, and deceptive interaction flows can manipulate users while remaining invisible to conventional security tools. WebShield fills this gap by translating low-level code patterns into human-interpretable security risks.

✨ Features

Real-time static analysis of HTML, CSS, JavaScript, and DOM structures

Heuristic and rule-based detection of deceptive UX and malicious patterns

Severity-weighted security scoring

Cross-layer correlation between markup, stylesheets, and scripts

Visual highlighting of suspicious DOM elements

Explainable vulnerability reporting for users and developers

🧮 Security Scoring Model

Each scan begins with a base score of 100.

Severity	Penalty
High	−10
Medium	−5
Low	−2

Example Finding

Issue: Anchor tag with empty href and no interaction handler

Category: UI Deception

Severity: Low

Impact: −2 points

These patterns are frequently used to mislead users through false affordances or interaction traps.

🧠 Architecture Overview

WebShield follows a layered, decoupled architecture designed for real-time analysis without blocking the browser UI.

Chrome Extension (Frontend)
extension/
├── popup.html        # User interface
├── popup.js          # Result rendering & scoring visualization
├── content.js        # DOM inspection & element highlighting


Captures live page metadata and DOM structures

Sends asynchronous scan requests to the backend API

Applies visual annotations to flagged elements

FastAPI Backend
backend/
├── scan_api.py       # API orchestration layer
├── parser_utils.py   # Metadata extraction (HTML, CSS, JS)
├── html_scanner.py   # HTML pattern analysis
├── css_scanner.py    # CSS pattern analysis
├── js_scanner.py     # JavaScript pattern analysis
├── issue_dict.py     # Issue aggregation & scoring logic


Fetches and normalizes raw web content

Downloads and analyzes external CSS resources

Executes modular scanners operating on raw source strings

Aggregates findings into a unified issue schema

🧮 Aggregation & Scoring Pipeline

Initialize score at 100

Execute modular scanners on raw metadata

Normalize findings into a consistent issue format

Apply severity-weighted deductions

Return explainable results as structured JSON

Scoring logic is deterministic and fully traceable.

🎯 Use Cases

Dark pattern and deceptive UX detection

Web security auditing and research

Ethical UI validation for developers

Security education and visualization

🛠️ Built With

Python

FastAPI

JavaScript

Chrome Extensions API

HTML & CSS

🚀 Roadmap

ML-based anomaly detection for unseen UX patterns

LLM-powered explainability layer using Gemini API

Adaptive scoring based on behavioral context

Expanded rule set for emerging deceptive design patterns


If you want next steps, I can:

Add architecture diagrams

Write contribution guidelines

Add a threat model section

Make this pass a security hiring manager skim test in 30 seconds

Just tell me 😄
