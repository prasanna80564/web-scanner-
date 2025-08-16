// Service worker state
const state = {
  vulnerabilities: [],
  isMonitoring: true
};

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  const data = await chrome.storage.local.get(['vulnerabilities', 'isMonitoring']);
  state.vulnerabilities = data.vulnerabilities || [];
  state.isMonitoring = data.isMonitoring !== false;
  updateBadge();
});


function updateBadge() {
  const count = state.isMonitoring ? state.vulnerabilities.length : 0;
  chrome.action.setBadgeText({
    text: count > 0 ? count.toString() : ""
  });
  chrome.action.setBadgeBackgroundColor({ color: '#EA4335' });
  chrome.storage.local.set({ 
    vulnerabilities: state.vulnerabilities, 
    isMonitoring: state.isMonitoring 
  });// Service worker state
const state = {
  vulnerabilities: [],
  isMonitoring: true
};

console.log('WebSecGuard background script starting...');

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  console.log('WebSecGuard extension installed');
  try {
    const data = await chrome.storage.local.get(['vulnerabilities', 'isMonitoring']);
    state.vulnerabilities = data.vulnerabilities || [];
    state.isMonitoring = data.isMonitoring !== false;
    updateBadge();
    console.log('Initialized with:', state);
  } catch (error) {
    console.error('Initialization error:', error);
  }
});


function updateBadge() {
  try {
    const count = state.isMonitoring ? state.vulnerabilities.length : 0;
    chrome.action.setBadgeText({
      text: count > 0 ? count.toString() : ""
    });
    chrome.action.setBadgeBackgroundColor({ color: '#EA4335' });
    chrome.storage.local.set({ 
      vulnerabilities: state.vulnerabilities, 
      isMonitoring: state.isMonitoring 
    });
  } catch (error) {
    console.error('Badge update error:', error);
  }
}

// Message handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received message:', request.type, 'from:', sender.tab?.url);
  
  try {
    switch (request.type) {
      case 'vulnerability_detected':
        handleVulnerabilityDetection(request, sender)
          .then(() => {
            console.log('Vulnerability processed successfully');
            sendResponse({ success: true });
          })
          .catch(error => {
            console.error('Vulnerability processing error:', error);
            sendResponse({ success: false, error: error.message });
          });
        return true; // Keep message channel open

      case 'get_vulnerabilities':
        console.log('Sending vulnerabilities:', state.vulnerabilities.length);
        sendResponse(state.vulnerabilities);
        break;

      case 'clear_vulnerabilities':
        state.vulnerabilities = [];
        updateBadge();
        console.log('Vulnerabilities cleared');
        sendResponse({ success: true });
        break;

      case 'toggle_monitoring':
        state.isMonitoring = !state.isMonitoring;
        updateBadge();
        console.log('Monitoring toggled to:', state.isMonitoring);
        sendResponse({ success: true, isMonitoring: state.isMonitoring });
        break;

      case 'get_monitoring_status':
        console.log('Sending monitoring status:', state.isMonitoring);
        sendResponse({ isMonitoring: state.isMonitoring });
        break;

      default:
        console.log('Unknown message type:', request.type);
        sendResponse({ success: false, error: 'Unknown message type' });
    }
  } catch (error) {
    console.error('Message handling error:', error);
    sendResponse({ success: false, error: error.message });
  }
});


async function handleVulnerabilityDetection(request, sender) {
  console.log('Processing vulnerability:', request.data);
  
  if (!state.isMonitoring) {
    console.log('Monitoring is disabled');
    return;
  }

 
  const existing = state.vulnerabilities.find(v => 
    v.type === request.data.type && 
    v.url === (sender.tab?.url || 'unknown') &&
    JSON.stringify(v.details) === JSON.stringify(request.data.details)
  );

  if (!existing) {
    const newVuln = {
      ...request.data,
      id: Date.now(),
      timestamp: new Date().toISOString(),
      url: sender.tab?.url || 'unknown',
      status: 'unverified'
    };
    
    state.vulnerabilities.push(newVuln);
    updateBadge();
    
    console.log('New vulnerability added:', newVuln);
    
    // Notify user for high severity
    if (request.data.severity === 'high') {
      try {
        await chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: 'Security Alert',
          message: `${newVuln.type} detected`
        });
      } catch (error) {
        console.error('Notification failed:', error);
      }
    }
  } else {
    console.log('Duplicate vulnerability ignored');
  }
}

// Keep service worker alive
chrome.alarms.create('keepAlive', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    console.log('Service worker kept alive');
    try {
      chrome.storage.local.set({ lastAlive: Date.now() });
    } catch (error) {
      console.error('Keep alive error:', error);
    }
  }
});

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  console.log('WebSecGuard extension started');
});

console.log('WebSecGuard background script loaded successfully');
}

// Message handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'vulnerability_detected':
      handleVulnerabilityDetection(request, sender)
        .then(() => sendResponse({ success: true }))
        .catch(error => sendResponse({ success: false, error }));
      return true;

    case 'get_vulnerabilities':
      sendResponse(state.vulnerabilities);
      break;

    case 'clear_vulnerabilities':
      state.vulnerabilities = [];
      updateBadge();
      sendResponse({ success: true });
      break;

    case 'toggle_monitoring':
      state.isMonitoring = !state.isMonitoring;
      updateBadge();
      sendResponse({ success: true, isMonitoring: state.isMonitoring });
      break;

    case 'update_vulnerability':
      handleUpdateVulnerability(request)
        .then(() => sendResponse({ success: true }))
        .catch(error => sendResponse({ success: false, error }));
      break;
  }
});

async function handleVulnerabilityDetection(request, sender) {
  if (!state.isMonitoring) return;

  const existing = state.vulnerabilities.find(v => 
    v.type === request.data.type && 
    v.url === (sender.tab?.url || 'unknown') &&
    JSON.stringify(v.details) === JSON.stringify(request.data.details)
  );

  if (!existing) {
    const newVuln = {
      ...request.data,
      id: Date.now(),
      timestamp: new Date().toISOString(),
      url: sender.tab?.url || 'unknown',
      status: 'unverified'
    };
    
    state.vulnerabilities.push(newVuln);
    updateBadge();
    
    if (request.data.severity === 'high') {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'Security Alert',
        message: `${newVuln.type} detected`
      });
    }
  }
}

async function handleUpdateVulnerability(request) {
  const index = state.vulnerabilities.findIndex(v => v.id === request.id);
  if (index !== -1) {
    state.vulnerabilities[index] = { 
      ...state.vulnerabilities[index], 
      ...request.updates 
    };
    await chrome.storage.local.set({ vulnerabilities: state.vulnerabilities });
  }
}

// CSRF detection
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!state.isMonitoring || details.method !== 'POST') return;

    const headers = {};
    if (details.requestHeaders) {
      for (const header of details.requestHeaders) {
        headers[header.name.toLowerCase()] = header.value;
      }
    }

    const verification = verifyCSRFProtection(headers, details);
    if (!verification.isProtected) {
      reportCSRFVulnerability(headers, details, verification);
    }
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders']
);

function verifyCSRFProtection(headers, details) {
  const result = {
    isProtected: false,
    missingProtections: [],
    verified: false
  };

  const headerNames = Object.keys(headers);
  const targetOrigin = new URL(details.url).origin;
  
  // Check for CSRF tokens
  const hasTokenHeader = headerNames.some(h => 
    h.includes('csrf') || h.includes('xsrf') || h.includes('anti-forgery')
  );
  
  // Check Origin header
  const originHeader = headers['origin'];
  if (originHeader) {
    result.verified = true;
    if (originHeader === targetOrigin) {
      result.isProtected = true;
      return result;
    }
  }
  
  // Check Referer header
  const refererHeader = headers['referer'];
  if (refererHeader) {
    result.verified = true;
    try {
      const refererOrigin = new URL(refererHeader).origin;
      if (refererOrigin === targetOrigin) {
        result.isProtected = true;
        return result;
      }
    } catch (e) {
      console.error('Error parsing referer:', e);
    }
  }

  // Check for API tokens
  if (headerNames.some(h => h.includes('authorization'))) {
    result.isProtected = true;
    return result;
  }

  // Check for custom headers
  if (headerNames.some(h => h.startsWith('x-') && h !== 'x-requested-with')) {
    result.isProtected = true;
    return result;
  }

  if (!hasTokenHeader) result.missingProtections.push('CSRF token header');
  if (!originHeader && !refererHeader) result.missingProtections.push('Origin/Referer header');

  return result;
}

function reportCSRFVulnerability(headers, details, verification) {
  const newVuln = {
    type: 'Potential CSRF',
    url: details.url,
    details: {
      method: details.method,
      missingProtections: verification.missingProtections,
      headers: Object.keys(headers),
      verification: verification
    },
    timestamp: new Date().toISOString(),
    severity: verification.verified ? 'high' : 'medium',
    status: 'unverified'
  };
  
  if (!state.vulnerabilities.some(v => 
    v.type === newVuln.type && 
    v.url === newVuln.url &&
    JSON.stringify(v.details) === JSON.stringify(newVuln.details)
  )) {
    state.vulnerabilities.push(newVuln);
    updateBadge();
  }
}

// Keep service worker alive
chrome.alarms.create('keepAlive', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    chrome.storage.local.set({ lastAlive: Date.now() });
  }
});