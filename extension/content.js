
const SEVERITY_COLORS = {
  high: '#ef4444',    // Red
  medium: '#f59e0b',  // Orange
  low: '#FFEEAC'      // yellow
};

let highlightOverlays = [];
let tooltip = null;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'highlight') {
    highlightIssues(request.issues);
    sendResponse({success: true});
  } else if (request.action === 'clear') {
    clearHighlights();
    sendResponse({success: true});
  }
  return true;
});

function highlightIssues(issues) {
  clearHighlights();
  
  issues.forEach((issue, index) => {
    if (!issue.element_selector) return;
    
    // Handle multiple selectors (comma-separated)
    const selectors = issue.element_selector.split(',').map(s => s.trim());
    
    selectors.forEach(selector => {
      try {
        const elements = document.querySelectorAll(selector);
        
        elements.forEach(element => {
          highlightElement(element, issue, index);
        });
      } catch (e) {
        console.warn(`Invalid selector: ${selector}`, e);
      }
    });
  });
}

function highlightElement(element, issue, index) {
  // Create overlay div
  const overlay = document.createElement('div');
  overlay.className = 'netshield-highlight';
  overlay.setAttribute('data-issue-index', index);
  
  const color = SEVERITY_COLORS[issue.severity] || SEVERITY_COLORS.medium;
  
  // Get element position
  const rect = element.getBoundingClientRect();
  const scrollX = window.pageXOffset || document.documentElement.scrollLeft;
  const scrollY = window.pageYOffset || document.documentElement.scrollTop;
  
  // Style the overlay
  overlay.style.cssText = `
    position: absolute;
    left: ${rect.left + scrollX}px;
    top: ${rect.top + scrollY}px;
    width: ${rect.width}px;
    height: ${rect.height}px;
    border: 2px solid ${color};
    background-color: ${color}15;
    pointer-events: auto;
    z-index: 999999;
    box-sizing: border-box;
    cursor: pointer;
    transition: all 0.2s ease;
  `;
  
  // Store issue data
  overlay.dataset.issue = JSON.stringify(issue);
  overlay.dataset.severity = issue.severity;
  
  // Hover effects
  overlay.addEventListener('mouseenter', (e) => {
    overlay.style.backgroundColor = `${color}25`;
    overlay.style.borderWidth = '3px';
    showTooltip(e, issue, color);
  });
  
  overlay.addEventListener('mouseleave', () => {
    overlay.style.backgroundColor = `${color}15`;
    overlay.style.borderWidth = '2px';
    hideTooltip();
  });
  
  overlay.addEventListener('mousemove', (e) => {
    if (tooltip) {
      updateTooltipPosition(e);
    }
  });
  
  document.body.appendChild(overlay);
  highlightOverlays.push(overlay);
  
  // Update position on scroll/resize
  const updatePosition = () => {
    const newRect = element.getBoundingClientRect();
    const newScrollX = window.pageXOffset || document.documentElement.scrollLeft;
    const newScrollY = window.pageYOffset || document.documentElement.scrollTop;
    
    overlay.style.left = `${newRect.left + newScrollX}px`;
    overlay.style.top = `${newRect.top + newScrollY}px`;
    overlay.style.width = `${newRect.width}px`;
    overlay.style.height = `${newRect.height}px`;
  };
  
  window.addEventListener('scroll', updatePosition, {passive: true});
  window.addEventListener('resize', updatePosition, {passive: true});
}

function showTooltip(event, issue, color) {
  // Remove existing tooltip
  if (tooltip) {
    tooltip.remove();
  }
  
  // Create tooltip
  tooltip = document.createElement('div');
  tooltip.className = 'netshield-tooltip';
  tooltip.style.cssText = `
    position: fixed;
    padding: 12px 16px;
    background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
    color: #e5e7eb;
    border: 1px solid ${color};
    border-radius: 8px;
    font-size: 12px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    white-space: nowrap;
    max-width: 350px;
    white-space: normal;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5), 0 0 8px ${color}40;
    z-index: 10000000;
    pointer-events: none;
    line-height: 1.5;
  `;
  
  const points = getPoints(issue.severity);
  
  tooltip.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
      <span style="
        padding: 4px 8px;
        background: ${color}20;
        color: ${color};
        border: 1px solid ${color}40;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      ">${issue.severity}</span>
      <span style="color: #9ca3af; font-size: 11px;">-${points} points</span>
    </div>
    <div style="font-weight: 600; margin-bottom: 6px; color: #e5e7eb;">${issue.issue}</div>
    <div style="
      display: inline-block;
      padding: 3px 8px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      font-size: 10px;
      color: #9ca3af;
      margin-top: 4px;
    ">${issue.category}</div>
  `;
  
  document.body.appendChild(tooltip);
  updateTooltipPosition(event);
}

function updateTooltipPosition(event) {
  if (!tooltip) return;
  
  const tooltipRect = tooltip.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  
  let left = event.clientX + 15;
  let top = event.clientY + 15;
  
  // Adjust if tooltip would go off screen
  if (left + tooltipRect.width > viewportWidth) {
    left = event.clientX - tooltipRect.width - 15;
  }
  
  if (top + tooltipRect.height > viewportHeight) {
    top = event.clientY - tooltipRect.height - 15;
  }
  
  // Keep within viewport
  left = Math.max(10, Math.min(left, viewportWidth - tooltipRect.width - 10));
  top = Math.max(10, Math.min(top, viewportHeight - tooltipRect.height - 10));
  
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
}

function hideTooltip() {
  if (tooltip) {
    tooltip.remove();
    tooltip = null;
  }
}

function clearHighlights() {
  highlightOverlays.forEach(overlay => overlay.remove());
  highlightOverlays = [];
  hideTooltip();
}

function getPoints(severity) {
  const points = {high: 10, medium: 5, low: 2};
  return points[severity] || 0;
}
