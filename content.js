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