/* core/dom_parser.js
 * Extracts DOM metadata and computed styles for each element on the page.
 * Designed to run inside a browser page (content script or DevTools console).
 * Attaches `extractDOMMetadata()` to `window.WebShield.extractDOMMetadata`.
 *
 * Output: an object { timestamp, url, title, viewport, elements: [...], scripts, iframes }
 * Each element feature contains boundingClientRect, computedStyle values, attributes, inline event handlers, and simple heuristics (isVisible, isClickable, isInViewport).
 */
