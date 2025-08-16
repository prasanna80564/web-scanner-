console.log('XSS detector starting...');


const reportedDetections = new Set();


const xssPatterns = [
  {
    name: 'XSS: Script Tag Injection',
    pattern: /<script[^>]*>.*?<\/script>/gi,
    validate: (match, context) => {
      // Only flag if it contains suspicious content, not just legitimate script tags
      const content = match.replace(/<script[^>]*>/gi, '').replace(/<\/script>/gi, '');
      return content.includes('alert(') || content.includes('prompt(') || content.includes('confirm(') || 
             content.includes('eval(') || content.includes('document.cookie') || content.includes('location.href');
    }
  },
  {
    name: 'XSS: Event Handler Injection',
    pattern: /on\w+\s*=\s*["'][^"']*["']/gi,
    validate: (match, context) => {
      // Only flag if it contains suspicious JavaScript
      const value = match.match(/on\w+\s*=\s*["']([^"']*)["']/i);
      if (!value) return false;
      const jsCode = value[1];
      return jsCode.includes('alert(') || jsCode.includes('prompt(') || jsCode.includes('confirm(') || 
             jsCode.includes('eval(') || jsCode.includes('document.cookie') || jsCode.includes('location.href');
    }
  },
  {
    name: 'XSS: JavaScript URI',
    pattern: /javascript:/gi,
    validate: (match, context) => {
      // Only flag if it's in a dangerous context
      return context.includes('href') || context.includes('src') || context.includes('action');
    }
  },
  {
    name: 'XSS: Dangerous HTML Tags',
    pattern: /<(iframe|embed|object)[^>]*>/gi,
    validate: (match, context) => {
      // Only flag if it has suspicious attributes
      return match.includes('src=') && (match.includes('javascript:') || match.includes('data:'));
    }
  }
];


function scanForXSS(html, context = 'HTML content') {
  const detections = [];
  
  xssPatterns.forEach(pattern => {
    const matches = html.match(pattern.pattern);
    if (matches) {
      matches.forEach(match => {
        // Only report if validation passes
        if (pattern.validate(match, context)) {
          detections.push({
            type: pattern.name,
            matched: match.slice(0, 100), // Limit length
            context: context,
            element: 'unknown'
          });
        }
      });
    }
  });
  
  return detections;
}


function scanAttributes(element) {
  const detections = [];
  const attributes = element.attributes;
  
  for (let i = 0; i < attributes.length; i++) {
    const attr = attributes[i];
    const value = attr.value;
    
    // Check for event handlers
    if (attr.name.startsWith('on') && attr.name.length > 2) {
      if (value.includes('alert(') || value.includes('prompt(') || value.includes('confirm(') || 
          value.includes('eval(') || value.includes('document.cookie') || value.includes('location.href')) {
        detections.push({
          type: 'XSS: Event Handler Injection',
          matched: `${attr.name}="${value}"`,
          context: `Attribute: ${attr.name}`,
          element: element.tagName
        });
      }
    }
    
   
    if (value.toLowerCase().startsWith('javascript:')) {
      detections.push({
        type: 'XSS: JavaScript URI',
        matched: `${attr.name}="${value}"`,
        context: `Attribute: ${attr.name}`,
        element: element.tagName
      });
    }
  }
  
  return detections;
}


function scanElement(element) {
  let detections = [];
  
  // Scan element content
  if (element.innerHTML) {
    detections = detections.concat(scanForXSS(element.innerHTML, `Element: ${element.tagName}`));
  }
  
  // Scan attributes
  detections = detections.concat(scanAttributes(element));
  
  return detections;
}


function reportDetection(detection) {
  // Create a unique key for this detection
  const detectionKey = `${detection.type}-${detection.matched}-${detection.context}`;
  
  // Skip if already reported
  if (reportedDetections.has(detectionKey)) {
    console.log('Skipping duplicate detection:', detectionKey);
    return;
  }
  

  reportedDetections.add(detectionKey);
  
  console.log('XSS Pattern matched:', detection.type, detection.matched);
  
  const message = {
    type: 'xss_detected',
    data: {
      type: detection.type,
      details: {
        matched: detection.matched,
        context: detection.context,
        element: detection.element,
        pageUrl: window.location.href
      },
      severity: 'high'
    }
  };
  
  console.log('Reporting XSS detection:', message);
  window.postMessage(message, '*');
}


function scanDocument() {
  const allElements = document.querySelectorAll('*');
  let totalDetections = 0;
  
  allElements.forEach(element => {
    const detections = scanElement(element);
    detections.forEach(detection => {
      reportDetection(detection);
      totalDetections++;
    });
  });
  
  if (totalDetections > 0) {
    console.log(`XSS scan complete: Found ${totalDetections} potential vulnerabilities`);
  } else {
    console.log('XSS scan complete: No vulnerabilities found');
  }
}


function watchForChanges() {
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const detections = scanElement(node);
          detections.forEach(detection => {
            reportDetection(detection);
          });
        }
      });
    });
  });
  
  observer.observe(document, {
    childList: true,
    subtree: true
  });
  
  return observer;
}

// Initialize
let observer;
try {
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      scanDocument();
      observer = watchForChanges();
    });
  } else {
    scanDocument();
    observer = watchForChanges();
  }
  
  console.log('XSS detector loaded and running');
} catch (error) {
  console.error('XSS detector error:', error);
}