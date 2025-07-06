let isMonitoring = true;
const debugMode = false;
const falsePositiveUrls = [
  'chrome://', 
  'about:',
  'edge://',
  'opera://',
  'moz-extension://',
  'chrome-extension://',
  'file://'
];

function initializeMonitoring() {
  chrome.runtime.sendMessage({ type: 'get_monitoring_status' }, (response) => {
    if (chrome.runtime.lastError) return;
    isMonitoring = response?.isMonitoring ?? true;
    if (debugMode) console.log('Monitoring status:', isMonitoring);
  });
}

function shouldIgnorePage() {
  const currentUrl = window.location.href;
  return falsePositiveUrls.some(url => currentUrl.startsWith(url)) || 
         !currentUrl.startsWith('http');
}

function injectXSSDetector() {
  if (shouldIgnorePage()) return;
  
  try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('injected.js');
    script.onload = () => {
      if (debugMode) console.log('XSS detector loaded');
      script.remove();
    };
    script.onerror = () => console.error('Failed to load XSS detector');
    (document.head || document.documentElement).appendChild(script);
  } catch (error) {
    console.error('Injection failed:', error);
  }
}

 Validate XSS detection patterns
function isValidXSSDetection(xssData) {
  if (!xssData?.details?.matched) return false;
  
  const ignoredPatterns = [
    /^https?:\/\//i,
    /^data:/i,
    /^blob:/i,
    /^chrome-extension:/i,
    /^moz-extension:/i
  ];
  
  return !ignoredPatterns.some(p => p.test(xssData.details.matched));
}

function handleXSSDetection(event) {
  if (shouldIgnorePage() || !isMonitoring) return;
  if (event.source !== window || event.data?.type !== 'xss_detected') return;
  
  const xssData = event.data.data;
  if (!isValidXSSDetection(xssData)) return;

  chrome.runtime.sendMessage({
    type: 'vulnerability_detected',
    data: {
      type: xssData.type || 'Unknown XSS',
      details: {
        ...xssData.details,
        pageUrl: window.location.href,
        element: xssData.element || 'unknown'
      },
      url: window.location.href,
      severity: xssData.severity || 'medium',
      isConfirmed: false
    }
  });


function checkForms() {
  if (shouldIgnorePage() || !isMonitoring) return;

  try {
    document.querySelectorAll('form').forEach(form => {
      if (form.method.toUpperCase() === 'POST' && 
          !shouldSkipForm(form) &&
          isLikelyCSRFVulnerable(form)) {
        checkCSRFToken(form);
      }
    });
  } catch (error) {
    if (debugMode) console.error('Form check error:', error);
  }
}

function checkCSRFToken(form) {
  const tokenData = checkForAntiCSRFTokens(form);
  if (!tokenData.hasToken) {
    chrome.runtime.sendMessage({
      type: 'vulnerability_detected',
      data: {
        type: 'Potential CSRF - Missing Token',
        details: {
          formAction: form.action,
          formMethod: form.method,
          reason: tokenData.reason,
          pageUrl: window.location.href
        },
        url: window.location.href,
        severity: 'high',
        isConfirmed: false
      }
    });
  }
}}

// Initialize the extension
function init() {
  if (shouldIgnorePage()) {
    if (debugMode) console.log('Skipping monitoring for internal page');
    return;
  }

  initializeMonitoring();
  injectXSSDetector();
  window.addEventListener('message', handleXSSDetection);
  checkForms();




init();