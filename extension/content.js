// extension/content.js
// Simple content script that uses the page-scoped WebShield.extractDOMMetadata function
// (our `core/dom_parser.js` attaches the function to window.WebShield.extractDOMMetadata when executed in page context).

(function(){
  try {
    if (window.WebShield && typeof window.WebShield.extractDOMMetadata === 'function') {
      const data = window.WebShield.extractDOMMetadata();
      // For now, just log it. Later we'll send this to the extension background or popup.
      console.info('WebShield DOM metadata extracted:', data);
    } else {
      console.warn('WebShield.extractDOMMetadata not found on this page. Make sure core/dom_parser.js is injected or run in page context.');
    }
  } catch (e) {
    console.error('WebShield content script error:', e);
  }
})();
