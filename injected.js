const xssPatterns = [
  { 
    pattern: /<script\b[^>]*>([\s\S]*?)<\/script>/gi, 
    type: "XSS: Script Tag Injection",
    severity: 'high'
  },
  { 
    pattern: /\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^"'\s>]*)/gi, 
    type: "XSS: Event Handler Injection",
    severity: 'high'
  },
  { 
    pattern: /javascript:\s*[^"'\s]+/gi, 
    type: "XSS: JavaScript URI Injection",
    severity: 'high'
  },
  { 
    pattern: /eval\s*\([^)]*\)/gi, 
    type: "XSS: Eval Function Usage",
    severity: 'medium'
  },
  { 
    pattern: /<(iframe|embed|object)\b[^>]*>/gi, 
    type: "XSS: Dangerous HTML Tag",
    severity: 'medium'
  }
];

function scanNode(node) {
  if (!node.outerHTML) return;

  // Check HTML content
  xssPatterns.forEach(({pattern, type, severity}) => {
    const matches = node.outerHTML.match(pattern);
    if (matches) {
      reportDetection({
        type: type,
        details: {
          matched: matches[0].slice(0, 200),
          context: "HTML content",
          element: node.tagName
        },
        severity: severity
      });
    }
  });

  // Check attributes
  if (node.attributes) {
    Array.from(node.attributes).forEach(attr => {
      xssPatterns.forEach(({pattern, type, severity}) => {
        if (pattern.test(attr.value)) {
          reportDetection({
            type: `${type} in attribute`,
            details: {
              attribute: attr.name,
              value: attr.value.slice(0, 200),
              element: node.tagName
            },
            severity: severity
          });
        }
      });
    });
  }
}

function reportDetection(data) {
  window.postMessage({
    type: "xss_detected",
    data: data
  }, "*");
}

const observer = new MutationObserver(mutations => {
  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        scanNode(node);
      }
    });
  });
});

observer.observe(document, {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ['onload', 'onerror', 'onclick', 'href', 'src']
});

// Initial scan
scanNode(document.documentElement);