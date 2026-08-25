const API_ENDPOINT = "http://127.0.0.1:5000/api/analysis/url";

document.addEventListener("DOMContentLoaded", async () => {
  const urlDisplay = document.getElementById("urlDisplay");
  const scanBtn = document.getElementById("scanBtn");
  const resultBox = document.getElementById("resultBox");
  const badgeClass = document.getElementById("badgeClass");
  const scoreVal = document.getElementById("scoreVal");
  const summaryText = document.getElementById("summaryText");
  const indicatorsSection = document.getElementById("indicatorsSection");
  const indicatorsList = document.getElementById("indicatorsList");

  let currentUrl = "";

  // Query active tab URL without accessing broader history
  if (chrome?.tabs?.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        currentUrl = tabs[0].url;
        urlDisplay.textContent = currentUrl;
      } else {
        urlDisplay.textContent = "Unable to retrieve active tab URL.";
      }
    });
  } else {
    currentUrl = "https://example.com/login-verification";
    urlDisplay.textContent = currentUrl;
  }

  scanBtn.addEventListener("click", async () => {
    if (!currentUrl || currentUrl.startsWith("chrome://")) {
      alert("Please open an external webpage to inspect.");
      return;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = "Evaluating Threat Signals...";

    try {
      const res = await fetch(API_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentUrl }),
      });

      if (!res.ok) {
        throw new Error(`API responded with ${res.status}`);
      }

      const data = await res.json();

      resultBox.style.display = "block";
      badgeClass.textContent = data.classification || "SAFE";
      badgeClass.className = `badge badge-${(data.classification || "safe").toLowerCase()}`;
      scoreVal.textContent = data.riskScore ?? 0;
      summaryText.textContent = data.summary || data.recommendation;

      if (data.indicators && data.indicators.length > 0) {
        indicatorsSection.style.display = "block";
        indicatorsList.innerHTML = data.indicators.map((ind) => `<li>${ind}</li>`).join("");
      } else {
        indicatorsSection.style.display = "none";
      }
    } catch (err) {
      resultBox.style.display = "block";
      badgeClass.textContent = "OFFLINE";
      badgeClass.className = "badge badge-suspicious";
      scoreVal.textContent = "-";
      summaryText.textContent = "AI CyberGuard API Server is not reachable on localhost:5000. Start the backend service.";
      indicatorsSection.style.display = "none";
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = "Re-inspect URL";
    }
  });
});
