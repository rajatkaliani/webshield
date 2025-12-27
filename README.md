
# NetShield 🛡️
A real-time client-side web security analyzer that scans webpages for
dark patterns and malicious components scoring security and highlighting malicious elements

WebShield is a Chrome extension that performs real-time security analysis
on live pages. It scans HTML, JavaScript, and CSS metadata for common dark patterns,
privacy, and UX-deception risks, then generates an explainable security score with highlighted malicious components. 

With a simple chrome extension, this is designed to help prevent malicious actors and cybersecurity risks worldwide.

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
- takes backend information and formats it into a readable and explainable scoring UI for user
- 
## Use Cases
- UX deception detection
- Security tooling research
