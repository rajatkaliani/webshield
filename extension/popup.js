// Clear highlights button
document.getElementById("clearBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { action: 'clear' }).catch(() => {});
    }
  });
});

// Fade-in animation on load
document.addEventListener('DOMContentLoaded', () => {
  document.body.style.opacity = '0';
  setTimeout(() => {
    document.body.style.transition = 'opacity 0.3s ease-in';
    document.body.style.opacity = '1';
  }, 10);
});

document.getElementById("scanBtn").addEventListener("click", async () => {
  const resultDiv = document.getElementById("result");
  const scoreDiv = document.getElementById("score");
  const summaryDiv = document.getElementById("summary");
  const issuesDiv = document.getElementById("issues");

  resultDiv.innerText = "Scanning...";
  scoreDiv.innerHTML = "";
  summaryDiv.innerHTML = "";
  issuesDiv.innerHTML = "";

  try {
    // Get current active tab
    const tabs = await new Promise((resolve, reject) => {
      try {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
          resolve(tabs);
        });
      } catch (e) {
        reject(e);
      }
    });

    const tab = tabs && tabs[0];
    if (!tab) throw new Error('No active tab found');

    // Check if URL is scannable
    const url = tab.url;
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
        url.startsWith('moz-extension://') || url.startsWith('file://') || 
        url.startsWith('about:')) {
      resultDiv.innerText = "Cannot scan this page. Please navigate to a regular website (http:// or https://).";
      return;
    }

    // Send scan request
    async function sendScanRequest(endpoint) {
      console.log('Sending scan request to', endpoint);
      const res = await fetch(endpoint + '/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });
      return res;
    }

    let response;
    try {
      response = await sendScanRequest('http://localhost:8000');
    } catch (errLocal) {
      console.warn('localhost request failed, trying 127.0.0.1:', errLocal);
      try {
        response = await sendScanRequest('http://127.0.0.1:8000');
      } catch (err127) {
        const msg = `Network error contacting scan server: ${err127.message || err127}`;
        resultDiv.innerText = msg;
        console.error('Scan request failed to both localhost and 127.0.0.1', errLocal, err127);
        return;
      }
    }

    // Handle errors
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      let errMsg = `Error: ${response.status} ${response.statusText}`;
      
      try {
        const errorData = JSON.parse(text);
        if (errorData.detail) {
          errMsg = errorData.detail;
        }
      } catch (e) {
        if (text) {
          errMsg = text;
        }
      }
      
      resultDiv.innerText = errMsg;
      console.error('Scan failed:', errMsg);
      return;
    }

    const data = await response.json();

    resultDiv.innerText = "Scan complete.";
    
    // Animate score count-up
    const score = data.score || 0;
    animateScore(scoreDiv, score);
    
    // Calculate point deductions
    function getPointsForSeverity(severity) {
      if (severity === "high") return 10;
      if (severity === "medium") return 5;
      if (severity === "low") return 2;
      return 0;
    }
    
    // Display summary with pills
    const issueCount = data.issue_count || 0;
    if (issueCount > 0) {
      const issues = data.issues || [];
      const highCount = issues.filter(i => i.severity === "high").length;
      const mediumCount = issues.filter(i => i.severity === "medium").length;
      const lowCount = issues.filter(i => i.severity === "low").length;
      
      summaryDiv.innerHTML = `
        <div class="summary-pills">
          <div class="pill pill-high">
            <span class="pill-dot"></span>
            <span>High: ${highCount}</span>
          </div>
          <div class="pill pill-medium">
            <span class="pill-dot"></span>
            <span>Medium: ${mediumCount}</span>
          </div>
          <div class="pill pill-low">
            <span class="pill-dot"></span>
            <span>Low: ${lowCount}</span>
          </div>
        </div>
      `;
      
      // Display all issues
      issuesDiv.innerHTML = '<div class="issues-header">Issue Details</div>';
      
      // Sort by severity (high first)
      const sortedIssues = [...issues].sort((a, b) => {
        const severityOrder = { "high": 0, "medium": 1, "low": 2 };
        return (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3);
      });
      
      sortedIssues.forEach((issue, index) => {
        const severity = issue.severity || "low";
        const points = getPointsForSeverity(severity);
        const category = issue.category || "unknown";
        
        const issueEl = document.createElement("div");
        issueEl.className = `issue-card issue-${severity}`;
        issueEl.style.opacity = '0';
        issueEl.style.transform = 'translateY(10px)';
        
        issueEl.innerHTML = `
          <div class="issue-header">
            <span class="issue-severity severity-${severity}">${severity}</span>
            <span class="issue-points">-${points} pts</span>
          </div>
          <div class="issue-description">${issue.issue}</div>
          <div class="issue-category">${category}</div>
        `;
        
        issuesDiv.appendChild(issueEl);
        
        // Fade-in animation
        setTimeout(() => {
          issueEl.style.transition = 'all 0.3s ease';
          issueEl.style.opacity = '1';
          issueEl.style.transform = 'translateY(0)';
        }, index * 30);
      });
    } else {
      summaryDiv.innerHTML = "";
      issuesDiv.innerHTML = '<div class="no-issues"><span style="font-size: 50px; display: block; margin-bottom: 12px; color:  #10b981;">&#10003;</span>No security issues found!</div>';
    }
    
    // Highlight issues on the page
    if (data.issues && data.issues.length > 0) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            action: 'highlight',
            issues: data.issues
          }).catch(err => {
            console.log('Could not send highlight message (page may not be ready):', err);
          });
        }
      });
    } else {
      // Clear highlights if no issues
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, { action: 'clear' }).catch(() => {});
        }
      });
    }

  } catch (err) {
    resultDiv.innerText = "Error scanning site.";
    console.error(err);
  }
});

// Score count-up animation
function animateScore(scoreDiv, targetScore) {
  let currentScore = 0;
  const duration = 800;
  const steps = 30;
  const increment = targetScore / steps;
  const stepDuration = duration / steps;
  
  // Determine score class
  let scoreClass = "score-excellent";
  if (targetScore < 50) {
    scoreClass = "score-danger";
  } else if (targetScore < 70) {
    scoreClass = "score-warning";
  } else if (targetScore < 90) {
    scoreClass = "score-good";
  }
  
  const interval = setInterval(() => {
    currentScore += increment;
    if (currentScore >= targetScore) {
      currentScore = targetScore;
      clearInterval(interval);
    }
    
    scoreDiv.innerHTML = `
      <div class="score-card ${scoreClass}">
        <div class="score-value">${Math.round(currentScore)}</div>
        <div class="score-label">Security Score</div>
      </div>
    `;
  }, stepDuration);
}
