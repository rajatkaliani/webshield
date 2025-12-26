// Simple scan button handler - no async/await, just callbacks
document.getElementById("scanBtn").addEventListener("click", function() {
  var resultDiv = document.getElementById("result");
  var scoreDiv = document.getElementById("score");

  resultDiv.innerText = "Scanning...";
  scoreDiv.innerText = "";

  // Get current tab
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (chrome.runtime.lastError || !tabs || !tabs[0]) {
      resultDiv.innerText = "Error: Could not get current tab";
      return;
    }

    var tab = tabs[0];
    var url = tab.url;

    // Try localhost first, then 127.0.0.1
    function sendScanRequest(endpoint) {
      return fetch(endpoint + '/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });
    }

    // Try localhost:8000
    sendScanRequest('http://localhost:8000')
      .then(function(response) {
        if (!response.ok) {
          throw new Error('Server error: ' + response.status);
        }
        return response.json();
      })
      .then(function(data) {
        resultDiv.innerText = "Scan complete.";
        scoreDiv.innerText = "Score: " + data.score;
      })
      .catch(function(err) {
        // If localhost fails, try 127.0.0.1
        console.warn('localhost failed, trying 127.0.0.1:', err);
        sendScanRequest('http://127.0.0.1:8000')
          .then(function(response) {
            if (!response.ok) {
              throw new Error('Server error: ' + response.status);
            }
            return response.json();
          })
          .then(function(data) {
            resultDiv.innerText = "Scan complete.";
            scoreDiv.innerText = "Score: " + data.score;
          })
          .catch(function(err2) {
            resultDiv.innerText = "Error: Could not connect to scan server";
            console.error('Scan failed:', err2);
          });
      });
  });
});
