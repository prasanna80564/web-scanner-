let isMonitoring = true;

console.log('WebSecGuard content script starting...');

// Initialize monitoring status
function initializeMonitoring() {
  try {
    chrome.runtime.sendMessage({ type: 'get_monitoring_status' }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('Failed to get monitoring status:', chrome.runtime.lastError);
        return;
      }
      isMonitoring = response?.isMonitoring ?? true;
      console.log('Monitoring status:', isMonitoring);
    });
  } catch (error) {
    console.error('Monitoring initialization error:', error);
  }
}

function injectXSSDetector() {
  try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('injected.js');
    script.onload = () => {
      console.log('XSS detector loaded successfully');
      script.remove();
    };
    script.onerror = () => console.error('Failed to load XSS detector');
    (document.head || document.documentElement).appendChild(script);
  } catch (error) {
    console.error('Injection failed:', error);
  }
}


function handleXSSDetection(event) {
  if (!isMonitoring) return;
  if (event.source !== window || event.data?.type !== 'xss_detected') return;
  
  const xssData = event.data.data;
  console.log('XSS detected:', xssData);

  try {
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
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('Failed to send vulnerability:', chrome.runtime.lastError);
      } else {
        console.log('Vulnerability sent successfully:', response);
      }
    });
  } catch (error) {
    console.error('Error sending vulnerability:', error);
  }
}


function findForms() {
  console.log('🔍 Searching for forms using multiple methods...');
  
  
  let forms = document.querySelectorAll('form');
  console.log(`Method 1 - querySelector: Found ${forms.length} forms`);
  
 
  if (forms.length === 0) {
    const allElements = document.getElementsByTagName('*');
    const formElements = Array.from(allElements).filter(el => el.tagName === 'FORM');
    forms = formElements;
    console.log(`Method 2 - getElementsByTagName: Found ${forms.length} forms`);
  }
  

  if (forms.length === 0) {
    const iframes = document.querySelectorAll('iframe');
    console.log(`Method 3 - Found ${iframes.length} iframes`);
    
    iframes.forEach((iframe, index) => {
      try {
        if (iframe.contentDocument) {
          const iframeForms = iframe.contentDocument.querySelectorAll('form');
          console.log(`Iframe ${index + 1}: Found ${iframeForms.length} forms`);
          if (iframeForms.length > 0) {
            forms = Array.from(iframeForms);
            console.log('✅ Forms found in iframe!');
          }
        }
      } catch (e) {
        console.log(`Iframe ${index + 1}: Cannot access (cross-origin)`);
      }
    });
  }
  
 
  if (forms.length === 0) {
    console.log('Method 4 - Checking for dynamic content...');
    // Wait a bit more and try again
    setTimeout(() => {
      const dynamicForms = document.querySelectorAll('form');
      console.log(`Dynamic check: Found ${dynamicForms.length} forms`);
      if (dynamicForms.length > 0) {
        checkFormsForCSRF(dynamicForms);
      }
    }, 3000);
  }
  
  // NEW: Method 5 - Check for CSRF vulnerabilities in other ways
  if (forms.length === 0) {
    console.log('Method 5 - Checking for CSRF vulnerabilities without forms...');
    checkForCSRFWithoutForms();
  }
  
  return forms;
}


function checkForCSRFWithoutForms() {
  console.log('🔍 Checking for CSRF vulnerabilities without forms...');
  
  // Check for AJAX requests that might be vulnerable
  const scripts = document.querySelectorAll('script');
  console.log(`Found ${scripts.length} script tags`);
  
  // Check for fetch/XMLHttpRequest calls
  const allText = document.body.innerText + document.head.innerText;
  if (allText.includes('fetch(') || allText.includes('XMLHttpRequest') || allText.includes('$.ajax')) {
    console.log('⚠️ Found potential AJAX calls - checking for CSRF protection...');
    
    // Check if there are any CSRF tokens in meta tags or global variables
    const metaTags = document.querySelectorAll('meta');
    let hasCSRFToken = false;
    
    metaTags.forEach(meta => {
      const name = meta.getAttribute('name') || '';
      const content = meta.getAttribute('content') || '';
      if (name.toLowerCase().includes('csrf') || name.toLowerCase().includes('token')) {
        console.log('✅ Found CSRF token in meta tag:', name, content);
        hasCSRFToken = true;
      }
    });
    
    if (!hasCSRFToken) {
      console.log('❌ No CSRF tokens found in meta tags');
      
      // Check for global CSRF tokens
      try {
        if (window.csrfToken || window.csrf_token || window._token) {
          console.log('✅ Found CSRF token in global variables');
          hasCSRFToken = true;
        }
      } catch (e) {
        console.log('Cannot access global variables (cross-origin)');
      }
      
      if (!hasCSRFToken) {
        console.log('⚠️ Potential CSRF vulnerability: AJAX calls without CSRF protection');
        
        // Report this as a potential CSRF vulnerability
        chrome.runtime.sendMessage({
          type: 'vulnerability_detected',
          data: {
            type: 'Potential CSRF - AJAX Without Token',
            details: {
              reason: 'Found AJAX calls but no CSRF tokens detected',
              pageUrl: window.location.href,
              pageContent: document.body.innerText.slice(0, 500) + '...'
            },
            url: window.location.href,
            severity: 'medium',
            isConfirmed: false
          }
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('❌ Failed to send CSRF vulnerability:', chrome.runtime.lastError);
          } else {
            console.log('✅ CSRF vulnerability sent successfully:', response);
          }
        });
      }
    }
  }
  
  
  console.log('🔍 Checking for JavaScript-created forms...');
  const formInputs = document.querySelectorAll('input[type="submit"], button[type="submit"], input[type="button"]');
  console.log(`Found ${formInputs.length} submit/button elements`);
  
  if (formInputs.length > 0) {
    console.log('⚠️ Found submit elements - checking if they trigger CSRF-vulnerable requests...');
    
    // Check if these elements are inside forms or trigger JavaScript
    formInputs.forEach((input, index) => {
      console.log(`Submit element ${index + 1}:`, input);
      console.log(`  Parent: ${input.parentElement?.tagName}`);
      console.log(`  Onclick: ${input.onclick}`);
      console.log(`  Type: ${input.type}`);
      
      // If it's not in a form, it might be JavaScript-triggered
      if (!input.closest('form')) {
        console.log(`  ⚠️ Submit element ${index + 1} is not in a form - potential CSRF vulnerability`);
        
        chrome.runtime.sendMessage({
          type: 'vulnerability_detected',
          data: {
            type: 'Potential CSRF - JavaScript Submit',
            details: {
              reason: 'Submit element not in form - may trigger CSRF-vulnerable requests',
              elementType: input.type,
              elementText: input.value || input.textContent || 'No text',
              pageUrl: window.location.href
            },
            url: window.location.href,
            severity: 'medium',
            isConfirmed: false
          }
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('❌ Failed to send CSRF vulnerability:', chrome.runtime.lastError);
          } else {
            console.log('✅ CSRF vulnerability sent successfully:', response);
          }
        });
      }
    });
  }
  
  
  console.log('🔍 Checking page for POST-like functionality...');
  const pageHTML = document.documentElement.outerHTML;
  
  if (pageHTML.includes('POST') || pageHTML.includes('post')) {
    console.log('⚠️ Found POST references - checking for CSRF protection...');
    
    // Look for any CSRF tokens in the page
    const csrfPatterns = [
      /csrf[_-]?token/gi,
      /xsrf[_-]?token/gi,
      /authenticity[_-]?token/gi,
      /anti[_-]?forgery/gi,
      /nonce/gi
    ];
    
    let hasCSRFProtection = false;
    csrfPatterns.forEach(pattern => {
      if (pattern.test(pageHTML)) {
        console.log('✅ Found CSRF protection pattern:', pattern.source);
        hasCSRFProtection = true;
      }
    });
    
    if (!hasCSRFProtection) {
      console.log('❌ No CSRF protection patterns found despite POST references');
      
      chrome.runtime.sendMessage({
        type: 'vulnerability_detected',
        data: {
          type: 'Potential CSRF - POST Without Protection',
          details: {
            reason: 'Found POST references but no CSRF protection patterns',
            pageUrl: window.location.href,
            pageContent: pageHTML.slice(0, 1000) + '...'
          },
          url: window.location.href,
          severity: 'high',
          isConfirmed: false
        }
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('❌ Failed to send CSRF vulnerability:', chrome.runtime.lastError);
        } else {
          console.log('✅ CSRF vulnerability sent successfully:', response);
        }
      });
    }
  }
}


function checkForms() {
  if (!isMonitoring) {
    console.log('❌ Monitoring is disabled, skipping CSRF check');
    return;
  }

  try {
    const forms = findForms();
    
    if (forms.length === 0) {
      console.log('🔍 No forms found on this page');
      return;
    }
    
    console.log(`🔍 CSRF Check: Found ${forms.length} forms`);
    checkFormsForCSRF(forms);
    
  } catch (error) {
    console.error('❌ Form check error:', error);
  }
}

function checkFormsForCSRF(forms) {
  forms.forEach((form, index) => {
    console.log(`🔍 Checking form ${index + 1}:`, form);
    console.log(`   Method: ${form.method}`);
    console.log(`   Action: ${form.action}`);
    
    // Check if it's a POST form
    if (form.method && form.method.toUpperCase() === 'POST') {
      console.log(`✅ Form ${index + 1} is POST - checking for CSRF protection`);
      checkCSRFToken(form);
    } else {
      console.log(`⏭️ Form ${index + 1} skipped - not POST method`);
    }
  });
}

function checkCSRFToken(form) {
  console.log('🔍 Checking CSRF token for form:', form);
  const tokenData = checkForAntiCSRFTokens(form);
  console.log('🔍 CSRF token check result:', tokenData);
  
  if (!tokenData.hasToken) {
    console.log('❌ CSRF vulnerability detected:', form);
    
    chrome.runtime.sendMessage({
      type: 'vulnerability_detected',
      data: {
        type: 'Potential CSRF - Missing Token',
        details: {
          formAction: form.action || 'No action',
          formMethod: form.method || 'No method',
          reason: tokenData.reason,
          pageUrl: window.location.href,
          formDescription: getFormDescription(form)
        },
        url: window.location.href,
        severity: 'high',
        isConfirmed: false
      }
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('❌ Failed to send CSRF vulnerability:', chrome.runtime.lastError);
      } else {
        console.log('✅ CSRF vulnerability sent successfully:', response);
      }
    });
  } else {
    console.log('✅ Form has CSRF protection');
  }
}


function checkForAntiCSRFTokens(form) {
  console.log('🔍 Checking form elements for CSRF tokens...');
  
  const tokenNames = ['csrf', 'xsrf', 'token', 'authenticity_token', 'anti-forgery', 'nonce', 'request_token'];
  
 
  console.log(`   Form has ${form.elements.length} elements`);
  for (const el of form.elements) {
    console.log(`   Checking element: ${el.name} (${el.type})`);
    if (el.name && tokenNames.some(name => el.name.toLowerCase().includes(name))) {
      console.log('✅ Found CSRF token field:', el.name);
      return { hasToken: true, fieldName: el.name };
    }
  }
  
  
  const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
  console.log(`   Found ${hiddenInputs.length} hidden inputs`);
  for (const input of hiddenInputs) {
    console.log(`   Checking hidden input: ${input.name}`);
    if (input.name && tokenNames.some(name => input.name.toLowerCase().includes(name))) {
      console.log('✅ Found CSRF token in hidden input:', input.name);
      return { hasToken: true, fieldName: input.name };
    }
  }
  
  
  const metaTags = document.querySelectorAll('meta[name*="csrf"], meta[name*="token"]');
  console.log(`   Found ${metaTags.length} relevant meta tags`);
  if (metaTags.length > 0) {
    console.log('✅ Found CSRF token in meta tag:', metaTags[0].getAttribute('name'));
    return { hasToken: true, source: 'meta tag' };
  }
  
  console.log('❌ No CSRF token found');
  return { hasToken: false, reason: 'No CSRF token field found' };
}


function getFormDescription(form) {
  try {
    // Get form purpose from labels or placeholders
    const labels = form.querySelectorAll('label');
    const inputs = form.querySelectorAll('input, textarea');
    
    let purpose = 'Form';
    if (labels.length > 0) {
      purpose = Array.from(labels).map(l => l.textContent.trim()).filter(t => t).join(', ');
    } else if (inputs.length > 0) {
      const placeholders = Array.from(inputs).map(i => i.placeholder).filter(p => p);
      if (placeholders.length > 0) {
        purpose = placeholders.join(', ');
      }
    }
    
    
    return purpose.replace(/\s+/g, ' ').trim();
  } catch (error) {
    return 'Form';
  }
}

// Initialize
function init() {
  console.log('Initializing WebSecGuard on:', window.location.href);
  
  try {
    initializeMonitoring();
    injectXSSDetector();
    window.addEventListener('message', handleXSSDetection);
    
    // Listen for monitoring changes
    chrome.runtime.onMessage.addListener((request) => {
      if (request.type === 'monitoring_updated') {
        isMonitoring = request.isMonitoring;
        console.log('Monitoring updated:', isMonitoring);
      }
    });
    
    
    setTimeout(() => {
      const debugBtn = document.createElement('button');
      debugBtn.textContent = '🔍 Debug Page Content';
      debugBtn.style.cssText = 'position:fixed;top:10px;right:10px;z-index:9999;background:red;color:white;padding:10px;border:none;border-radius:5px;cursor:pointer;';
      debugBtn.onclick = () => {
        console.log('=== PAGE DEBUG INFO ===');
        console.log('URL:', window.location.href);
        console.log('Title:', document.title);
        console.log('Forms:', document.querySelectorAll('form').length);
        console.log('Inputs:', document.querySelectorAll('input').length);
        console.log('Buttons:', document.querySelectorAll('button').length);
        console.log('Scripts:', document.querySelectorAll('script').length);
        console.log('Body text preview:', document.body.innerText.slice(0, 500));
        console.log('HTML preview:', document.documentElement.outerHTML.slice(0, 1000));
        console.log('======================');
      };
      document.body.appendChild(debugBtn);
      console.log('Debug button added');
    }, 2000);
    
   
    console.log('🔍 Will check for forms in 1 second...');
    setTimeout(() => {
      checkForms();
    }, 1000);
    
    console.log('🔍 Will check for forms in 3 seconds...');
    setTimeout(() => {
      checkForms();
    }, 3000);
    
    console.log('🔍 Will check for forms in 5 seconds...');
    setTimeout(() => {
      checkForms();
    }, 5000);
    
    // Watch for dynamically added forms
    const formObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (node.tagName === 'FORM') {
              console.log('✅ New form detected, checking for CSRF...');
              setTimeout(() => checkForms(), 100);
            }
          }
        });
      });
    });
    
    formObserver.observe(document, {
      childList: true,
      subtree: true
    });
    
  } catch (error) {
    console.error('Initialization error:', error);
  }
}

// Start
init();