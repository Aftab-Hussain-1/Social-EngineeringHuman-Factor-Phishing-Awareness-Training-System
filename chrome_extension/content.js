
// Content Script - Detects fake login pages (FR1-FR7)
class PhishingDetector {
  constructor() {
    this.knownDomains = {
      'google.com': ['google', 'gmail', 'sign in'],
      'facebook.com': ['facebook', 'log in', 'connect'],
      'instagram.com': ['instagram', 'log in'],
      'twitter.com': ['twitter', 'log in', 'sign in'],
      'linkedin.com': ['linkedin', 'sign in'],
      'microsoft.com': ['microsoft', 'outlook', 'sign in'],
      'apple.com': ['apple', 'sign in', 'apple id'],
      'amazon.com': ['amazon', 'sign in'],
      'paypal.com': ['paypal', 'log in'],
      'github.com': ['github', 'sign in']
    };
    this.whitelistedDomains = [];
    this.riskBehaviors = [];
    this.init();
  }

  init() {
    this.loadWhitelist();
    this.detectLoginForms();
    this.setupFormMonitoring();
  }

  // FR1: Detects <form> with password fields
  detectLoginForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const passwordFields = form.querySelectorAll('input[type="password"]');
      if (passwordFields.length > 0) {
        this.analyzeForm(form);
      }
    });
  }

  // FR2: Extracts title, headers, logos
  extractPageBranding() {
    const title = document.title.toLowerCase();
    const headers = Array.from(document.querySelectorAll('h1, h2, h3'))
      .map(h => h.textContent.toLowerCase());
    
    const logos = Array.from(document.querySelectorAll('img'))
      .filter(img => img.alt && (
        img.alt.toLowerCase().includes('logo') || 
        img.className.toLowerCase().includes('logo')
      ))
      .map(img => img.alt.toLowerCase());

    return { title, headers: headers.join(' '), logos: logos.join(' ') };
  }

  // FR3 & FR4: Compares branding with domain and alerts on mismatch
  analyzeForm(form) {
    const currentDomain = window.location.hostname.toLowerCase();
    const branding = this.extractPageBranding();
    
    if (this.isWhitelisted(currentDomain)) {
      return;
    }

    const suspiciousIndicators = this.checkForSuspiciousIndicators(currentDomain, branding);
    
    if (suspiciousIndicators.length > 0) {
      this.logRiskyBehavior({
        type: 'suspicious_login_page',
        domain: currentDomain,
        indicators: suspiciousIndicators,
        timestamp: new Date().toISOString()
      });
      
      this.showWarning(form, suspiciousIndicators);
    }
  }

  checkForSuspiciousIndicators(domain, branding) {
    const indicators = [];
    const allText = `${branding.title} ${branding.headers} ${branding.logos}`.toLowerCase();
    
    // Check if page claims to be a known service but domain doesn't match
    for (const [trustedDomain, keywords] of Object.entries(this.knownDomains)) {
      if (!domain.includes(trustedDomain)) {
        for (const keyword of keywords) {
          if (allText.includes(keyword)) {
            indicators.push(`Claims to be ${trustedDomain} but domain is ${domain}`);
            break;
          }
        }
      }
    }

    // Check for suspicious domain patterns
    if (this.hasSuspiciousDomainPattern(domain)) {
      indicators.push('Suspicious domain pattern detected');
    }

    return indicators;
  }

  hasSuspiciousDomainPattern(domain) {
    const suspiciousPatterns = [
      /\d+\.\d+\.\d+\.\d+/, // IP addresses
      /[a-z]+-[a-z]+\.(tk|ml|ga|cf)$/, // Suspicious TLDs
      /[a-z]+[0-9]+\.(com|net|org)$/, // Numbers in domain
      /.{20,}/, // Very long domains
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(domain));
  }

  // FR7: Optionally blocks form submission
  setupFormMonitoring() {
    document.addEventListener('submit', (event) => {
      const form = event.target;
      const passwordFields = form.querySelectorAll('input[type="password"]');
      
      if (passwordFields.length > 0) {
        const currentDomain = window.location.hostname.toLowerCase();
        
        if (!this.isWhitelisted(currentDomain) && this.isHighRisk(currentDomain)) {
          event.preventDefault();
          this.showBlockWarning();
          
          this.logRiskyBehavior({
            type: 'attempted_login_on_suspicious_site',
            domain: currentDomain,
            blocked: true,
            timestamp: new Date().toISOString()
          });
        }
      }
    });
  }

  isHighRisk(domain) {
    const branding = this.extractPageBranding();
    const indicators = this.checkForSuspiciousIndicators(domain, branding);
    return indicators.length >= 2; // High risk if multiple indicators
  }

  showWarning(form, indicators) {
    const warning = document.createElement('div');
    warning.id = 'phishing-warning';
    warning.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: #e74c3c;
      color: white;
      padding: 15px;
      text-align: center;
      z-index: 999999;
      font-family: Arial, sans-serif;
      font-size: 14px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    `;
    
    warning.innerHTML = `
      <strong>⚠️ PHISHING WARNING</strong><br>
      This page may be impersonating a legitimate service.<br>
      Issues detected: ${indicators.join(', ')}<br>
      <button onclick="this.parentElement.remove()" style="margin: 5px; padding: 5px 10px; background: white; color: #e74c3c; border: none; border-radius: 3px;">Dismiss</button>
      <button onclick="window.phishingDetector.whitelist('${window.location.hostname}')" style="margin: 5px; padding: 5px 10px; background: #27ae60; color: white; border: none; border-radius: 3px;">Trust This Site</button>
      <button onclick="window.phishingDetector.reportSite()" style="margin: 5px; padding: 5px 10px; background: #f39c12; color: white; border: none; border-radius: 3px;">Report</button>
    `;
    
    document.body.insertBefore(warning, document.body.firstChild);
  }

  showBlockWarning() {
    alert('🚫 LOGIN BLOCKED\n\nThis site appears to be impersonating a legitimate service. Your login attempt has been blocked for your protection.\n\nIf you believe this is a legitimate site, you can whitelist it using the extension popup.');
  }

  // FR5: Allows whitelisting
  whitelist(domain) {
    if (!this.whitelistedDomains.includes(domain)) {
      this.whitelistedDomains.push(domain);
      chrome.storage.local.set({ whitelistedDomains: this.whitelistedDomains });
    }
    
    const warning = document.getElementById('phishing-warning');
    if (warning) warning.remove();
  }

  isWhitelisted(domain) {
    return this.whitelistedDomains.includes(domain);
  }

  loadWhitelist() {
    chrome.storage.local.get(['whitelistedDomains'], (result) => {
      this.whitelistedDomains = result.whitelistedDomains || [];
    });
  }

  // FR6: Allows reporting
  reportSite() {
    const data = {
      url: window.location.href,
      domain: window.location.hostname,
      title: document.title,
      timestamp: new Date().toISOString(),
      branding: this.extractPageBranding()
    };
    
    // Send to backend for analysis
    fetch('https://employee-risk-calculator--5000.prod1b.defang.dev/api/report-phishing', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(data)
    }).then(() => {
      alert('Thank you for reporting this site. It will be reviewed by our security team.');
    }).catch(() => {
      console.log('Failed to report site - offline mode');
    });
  }

  // FR11: Log risky clicks or behavior
  logRiskyBehavior(behavior) {
    this.riskBehaviors.push(behavior);
    
    // Send to backend for risk scoring
    fetch('https://employee-risk-calculator--5000.prod1b.defang.dev/api/log-behavior', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(behavior)
    }).catch(() => {
      // Store locally if offline
      chrome.storage.local.get(['riskBehaviors'], (result) => {
        const behaviors = result.riskBehaviors || [];
        behaviors.push(behavior);
        chrome.storage.local.set({ riskBehaviors: behaviors });
      });
    });
  }
}

// Initialize detector
window.phishingDetector = new PhishingDetector();
