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