
# WebShield 🛡️
📌 WebShield

WebShield is a Chrome browser extension + backend scanner that performs real-time security analysis of web pages. It inspects HTML, CSS, and JavaScript to detect dark patterns, deceptive UX, and malicious components, then generates a transparent security score along with categorized issue highlights.

Why this matters
Web threats aren’t only overt malware. Many harmful experiences hide in deceptive UI/UX or subtle script-based manipulations. WebShield helps users and developers understand and visualize these issues with an easy-to-interpret score and annotations.

Key Features

Real-time scanning of loaded web content

Rule-based vulnerability detection

Scoring based on severity (high/medium/low)

Visual highlighting of suspicious elements

Explainable feedback for users

Built With
Python · FastAPI · Chrome extension · JavaScript · HTML & CSS

## WATCH THIS ##

https://youtu.be/4--ddW2lfLc

## WATCH THIS ##

<img width="360" height="510" alt="image" src="https://github.com/user-attachments/assets/3fcb0a0d-18a4-43bd-a499-08726dbfef4c" />

<img width="379" height="604" alt="image" src="https://github.com/user-attachments/assets/c2e484a7-f682-47ff-a23a-4b3bc246dfde" />

## Key Features:

- Real-time HTML, CSS, JS, DOM scanning
- Rule-based vulnerability detection
- Low, Medium, High weighted scoring
- Issue categorization (User explainability)
- ## User-friendly UI

## Security Scoring Logic
WebShield starts each scan with a base score of **100**.

| Severity | Penalty |
|--------|---------|
| High   | −10     |
| Medium | −5      |
| Low    | −2      |

## Example:
**Issue:** Link with empty href and no interaction handler  
**Category:** UI Deception  
**Severity:** Low  
**Impact:** −2 points  

These patterns can mislead users and are often used in deceptive interfaces.


## Architecture

### Layered Architecture


## extension/popup.html` and `extension/popup.js` 
- Handles user interaction and displays scan results, managing button clicks 

## extension/popup.js and extension/content.js
- Sends scan request to API
- content.js applies the recognized malicious content and applies highlighting logic

## scan_api.py
- FastAPI server
- Fetches and scans content returning into JSON response

## parser_utils.py
- Fetches all metadata from the website (HTML, CSS, JS)
- Downloads external CSS
- returns raw metadata content to be parsed and analyzed

## backend/html_scanner.py backend/js_scanner.py backend/css_scanner.py
- Analyzes all three parts of metadata
- Each scanner operates on raw strings and returns issue dictionaries
- uses issue_dict for analyzing

## backend/issue_dict.py

- aggregates all issues into a consistently formatted list
- pushed into scoring layer

## backend/issue_dict.py::compute_score()
- Weighted point deduction from 100 based off of severity
- Iterates through issue_dict

## extension/popup.js
- takes backend information and formats it into a readable and explainable scoring UI for the user

## Use Cases
- UX deception detection
- Security tooling research

## Future implementation:
- ML for anomoly detection
- Gemini API for better explainability and user knowledge
