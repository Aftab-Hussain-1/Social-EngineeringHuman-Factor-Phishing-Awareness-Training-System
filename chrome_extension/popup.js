
document.addEventListener('DOMContentLoaded', function() {
  const statusEl = document.getElementById('statusText');
  const trustBtn = document.getElementById('trustSite');
  const reportBtn = document.getElementById('reportSite');
  const whitelistEl = document.getElementById('whitelistItems');
  const clearBtn = document.getElementById('clearWhitelist');

  let currentTab;

  // Get current tab
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    currentTab = tabs[0];
    const url = new URL(currentTab.url);
    const domain = url.hostname;

    checkSiteStatus(domain);
  });

  function checkSiteStatus(domain) {
    chrome.storage.local.get(['whitelistedDomains'], function(result) {
      const whitelist = result.whitelistedDomains || [];

      if (whitelist.includes(domain)) {
        statusEl.textContent = '✅ Trusted Site';
        document.getElementById('status').className = 'status';
      } else {
        // Check if potentially suspicious
        const suspicious = checkSuspiciousDomain(domain);
        if (suspicious) {
          statusEl.textContent = '⚠️ Potentially Suspicious';
          document.getElementById('status').className = 'status warning';
        } else {
          statusEl.textContent = '🔍 Unknown Site';
          document.getElementById('status').className = 'status';
        }
      }

      loadWhitelist(whitelist);
    });
  }

  function checkSuspiciousDomain(domain) {
    const suspiciousPatterns = [
      /\d+\.\d+\.\d+\.\d+/,
      /[a-z]+-[a-z]+\.(tk|ml|ga|cf)$/,
      /[a-z]+[0-9]+\.(com|net|org)$/,
      /.{20,}/
    ];

    return suspiciousPatterns.some(pattern => pattern.test(domain));
  }

  function loadWhitelist(whitelist) {
    whitelistEl.innerHTML = '';
    whitelist.forEach(domain => {
      const item = document.createElement('div');
      item.className = 'domain-item';
      item.innerHTML = `
        <span>${domain}</span>
        <button class="btn btn-danger" onclick="removeDomain('${domain}')">Remove</button>
      `;
      whitelistEl.appendChild(item);
    });
  }

  trustBtn.addEventListener('click', function() {
    const url = new URL(currentTab.url);
    const domain = url.hostname;

    chrome.storage.local.get(['whitelistedDomains'], function(result) {
      const whitelist = result.whitelistedDomains || [];
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        chrome.storage.local.set({ whitelistedDomains: whitelist }, function() {
          checkSiteStatus(domain);
        });
      }
    });
  });

  reportBtn.addEventListener('click', function() {
    // Send report to content script
    chrome.tabs.sendMessage(currentTab.id, { action: 'reportSite' });
    window.close();
  });

  clearBtn.addEventListener('click', function() {
    chrome.storage.local.set({ whitelistedDomains: [] }, function() {
      loadWhitelist([]);
    });
  });

  // chrome_extension/popup.js

  document.addEventListener('DOMContentLoaded', function() {
    chrome.storage.local.get(['needs_login'], function(result) {
      if (result.needs_login) {
        alert('Please log in to use the extension features.');
        // Optionally, redirect to the login page or show a login form.
      }
    });

    // The rest of your popup code...
  });

  // Global function for removing domains
  window.removeDomain = function(domain) {
    chrome.storage.local.get(['whitelistedDomains'], function(result) {
      const whitelist = result.whitelistedDomains || [];
      const updated = whitelist.filter(d => d !== domain);
      chrome.storage.local.set({ whitelistedDomains: updated }, function() {
        loadWhitelist(updated);
      });
    });
  };
});
