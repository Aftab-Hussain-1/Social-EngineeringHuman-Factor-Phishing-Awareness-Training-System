
// Background Service Worker
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detector Extension Installed');

  // Set default badge
  chrome.action.setBadgeText({ text: '🛡️' });
  chrome.action.setBadgeBackgroundColor({ color: '#00cec9' });
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    try {
      const url = new URL(tab.url);
      const domain = url.hostname;

      // Check if domain is suspicious
      if (isSuspiciousDomain(domain)) {
        chrome.action.setBadgeText({ text: '⚠️', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#e74c3c', tabId: tabId });
      } else {
        chrome.action.setBadgeText({ text: '🛡️', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#00cec9', tabId: tabId });
      }
    } catch (e) {
      // Invalid URL
    }
  }
});

function isSuspiciousDomain(domain) {
  const suspiciousPatterns = [
    /\d+\.\d+\.\d+\.\d+/, // IP addresses
    /[a-z]+-[a-z]+\.(tk|ml|ga|cf)$/, // Suspicious TLDs
    /[a-z]+[0-9]+\.(com|net|org)$/, // Numbers in domain
    /.{20,}/, // Very long domains
  ];

  return suspiciousPatterns.some(pattern => pattern.test(domain));
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'logBehavior') {
    // Store risky behavior
    chrome.storage.local.get(['riskBehaviors'], (result) => {
      const behaviors = result.riskBehaviors || [];
      behaviors.push(request.data);
      chrome.storage.local.set({ riskBehaviors: behaviors });
    });
  }
});

// chrome_extension/background.js

chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detector Extension Installed');

  // Check for user authentication
  checkUserAuthentication();
});

// Check User Authentication
function checkUserAuthentication() {
  fetch('https://employee-risk-calculator--5000.prod1b.defang.dev/api/check-auth', { // Your Flask API endpoint
    method: 'GET',
    credentials: 'include',
  })
    .then(response => {
      if (response.ok) {
        return response.json();
      }
      throw new Error('User not authenticated');
    })
    .then(data => {
      if (!data.is_authenticated) {
        chrome.storage.local.set({ 'needs_login': true });
        console.log('User is not authenticated. Prompting to log in.');
      }
    })
    .catch(error => {
      console.error('Error checking authentication:', error);
    });
}