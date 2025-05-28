import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * Register all resources with the MCP server
 */
export function registerResources(server: McpServer) {
  // Register cybersecurity checklists resource
  server.resource(
    "cybersecurity_checklists",
    new ResourceTemplate("cybersecurity://checklists/{category}", { 
      list: async () => {
        const categories = ["authentication", "injection", "data_leakage", "rate_limiting", "general"];
        return {
          resources: categories.map(category => ({
            uri: `cybersecurity://checklists/${category}`,
            name: `${category.charAt(0).toUpperCase() + category.slice(1).replace('_', ' ')} Security Checklist`,
            description: `Security checklist for ${category.replace('_', ' ')} vulnerabilities`,
            mimeType: "text/markdown"
          }))
        };
      }
    }),
    async (uri, { category }) => {
      const checklists = getChecklist(category as string);
      
      return {
        contents: [{
          uri: uri.href,
          text: checklists,
          mimeType: "text/markdown"
        }]
      };
    }
  );

  // Register API testing guide resource
  server.resource(
    "testing_guides",
    new ResourceTemplate("guides://api-testing/{topic}", { 
      list: async () => {
        const topics = ["jwt-testing", "auth-bypass", "sql-injection", "xss", "rate-limiting"];
        return {
          resources: topics.map(topic => ({
            uri: `guides://api-testing/${topic}`,
            name: `${topic.charAt(0).toUpperCase() + topic.slice(1).replace('-', ' ')} Testing Guide`,
            description: `Comprehensive guide for testing ${topic.replace('-', ' ')} vulnerabilities`,
            mimeType: "text/markdown"
          }))
        };
      }
    }),
    async (uri, { topic }) => {
      const guide = getGuide(topic as string);
      
      return {
        contents: [{
          uri: uri.href,
          text: guide,
          mimeType: "text/markdown"
        }]
      };
    }
  );
}

/**
 * Get security checklist content for specific category
 */
function getChecklist(category: string): string {
  const checklists: Record<string, string> = {
    "authentication": `
# API Authentication Security Checklist

## Authentication Mechanisms
- [ ] Implement proper OAuth 2.0 flow if applicable
- [ ] Use industry standard JWT implementation
- [ ] Enforce strong password policies
- [ ] Implement multi-factor authentication where possible
- [ ] Use HTTPS for all authentication requests

## Token Management
- [ ] Set appropriate token expiration times
- [ ] Implement token refresh mechanism
- [ ] Store tokens securely (HttpOnly cookies)
- [ ] Implement token revocation
- [ ] Include proper JWT claims (iss, sub, exp, iat)

## Error Handling
- [ ] Use generic error messages for failed authentication
- [ ] Implement account lockout after failed attempts
- [ ] Log authentication attempts for auditing
- [ ] Don't expose sensitive data in error messages

## Security Headers
- [ ] Set proper CORS headers
- [ ] Implement CSP headers
- [ ] Use X-XSS-Protection header
- [ ] Implement HTTP Strict Transport Security (HSTS)
`,

    "injection": `
# API Injection Security Checklist

## Input Validation
- [ ] Validate all input parameters
- [ ] Use parameterized queries for database operations
- [ ] Implement input sanitization
- [ ] Validate data types, length, and format
- [ ] Use allowlist approach for input validation

## SQL Injection Prevention
- [ ] Use ORM libraries when possible
- [ ] Implement prepared statements
- [ ] Use stored procedures
- [ ] Limit database privileges
- [ ] Validate and sanitize user input

## NoSQL Injection Prevention
- [ ] Validate and sanitize input for NoSQL operations
- [ ] Use secure MongoDB operators
- [ ] Apply the principle of least privilege
- [ ] Use schema validation

## Command Injection Prevention
- [ ] Avoid system calls when possible
- [ ] Use command parameter arrays instead of strings
- [ ] Implement input validation for command parameters
- [ ] Use allowlist for command inputs
`,

    "data_leakage": `
# API Data Leakage Prevention Checklist

## Response Control
- [ ] Implement proper authorization checks
- [ ] Use field-level permissions
- [ ] Filter sensitive data from responses
- [ ] Implement API versioning
- [ ] Control HTTP response headers

## Error Handling
- [ ] Use generic error messages
- [ ] Don't expose stack traces or detailed errors
- [ ] Log errors securely
- [ ] Implement proper exception handling
- [ ] Return appropriate HTTP status codes

## Data Masking
- [ ] Mask sensitive data in responses (e.g., PII)
- [ ] Implement data redaction for logs
- [ ] Use data minimization principles
- [ ] Apply principle of least privilege
- [ ] Implement proper data classification
`,

    "rate_limiting": `
# API Rate Limiting Checklist

## Implementation
- [ ] Implement rate limiting per user/IP
- [ ] Use token bucket or leaky bucket algorithms
- [ ] Set appropriate rate limits based on resource sensitivity
- [ ] Implement exponential backoff for repeated violations
- [ ] Log rate limit violations

## Response Headers
- [ ] Include X-RateLimit-Limit header
- [ ] Include X-RateLimit-Remaining header
- [ ] Include X-RateLimit-Reset header
- [ ] Return 429 Too Many Requests status code
- [ ] Provide clear error message for rate limit violations

## Advanced Techniques
- [ ] Implement different limits for different endpoints
- [ ] Use sliding window rate limiting
- [ ] Consider implementing API quotas
- [ ] Implement circuit breaker pattern
- [ ] Monitor and analyze rate limit effectiveness
`,

    "general": `
# General API Security Checklist

## Authentication
- [ ] Use industry standard authentication methods
- [ ] Implement proper token management
- [ ] Require strong passwords
- [ ] Implement MFA where possible

## Authorization
- [ ] Implement role-based access control
- [ ] Validate authorization on every request
- [ ] Use principle of least privilege
- [ ] Implement resource-based authorization

## Data Validation
- [ ] Validate all input
- [ ] Implement proper error handling
- [ ] Use parameterized queries
- [ ] Sanitize user input

## Transport Security
- [ ] Use HTTPS exclusively
- [ ] Implement proper TLS configuration
- [ ] Use secure cookies
- [ ] Implement HTTP security headers

## Monitoring and Logging
- [ ] Log security events
- [ ] Implement audit trails
- [ ] Monitor for suspicious activities
- [ ] Set up alerts for security violations
`,
  };

  return checklists[category] || "Checklist not found for the specified category.";
}

/**
 * Get guide content for specific API testing topic
 */
function getGuide(topic: string): string {
  const guides: Record<string, string> = {
    "jwt-testing": `
# JWT Security Testing Guide

## Overview
JSON Web Tokens (JWT) are a popular method for transmitting information securely between parties. However, improper implementation can lead to serious security vulnerabilities.

## Common JWT Vulnerabilities

### 1. Algorithm Confusion Attacks
**What to test:**
- Change the algorithm from RS256 to HS256
- Set algorithm to "none"
- Use empty signature

**Test steps:**
1. Decode the JWT header and payload
2. Modify the "alg" field in the header
3. Re-encode and send the modified token
4. Observe if the application accepts the token

### 2. Weak Secret Keys
**What to test:**
- Brute force weak signing keys
- Use common passwords as signing keys

**Test steps:**
1. Extract the JWT signature
2. Attempt to crack the signing key using tools like hashcat
3. Use common passwords and dictionary attacks

### 3. Key Confusion
**What to test:**
- Use public key as HMAC secret
- Confusion between different key types

### 4. JWT Injection
**What to test:**
- Modify claims to escalate privileges
- Change user ID or role information
- Extend token expiration

**Example payload manipulation:**
\`\`\`json
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin",  // Changed from "user"
  "iat": 1516239022
}
\`\`\`

## Testing Tools
- jwt.io - For decoding and encoding JWTs
- hashcat - For cracking weak keys
- Burp Suite - JWT extension for testing
- Custom scripts for automated testing

## Recommendations
- Use strong, random signing keys
- Implement proper algorithm validation
- Set appropriate token expiration times
- Validate all JWT claims server-side
`,

    "auth-bypass": `
# Authentication Bypass Testing Guide

## Overview
Authentication bypass vulnerabilities allow attackers to access protected resources without proper authentication.

## Common Authentication Bypass Techniques

### 1. Direct Object Reference
**What to test:**
- Access protected resources directly
- Modify user IDs in requests
- Use predictable resource identifiers

**Test steps:**
1. Identify protected endpoints
2. Try accessing them without authentication
3. Modify user identifiers in authenticated requests
4. Test for predictable patterns in resource IDs

### 2. Parameter Pollution
**What to test:**
- Duplicate authentication parameters
- Use different parameter names
- URL encoding attacks

**Examples:**
\`\`\`
POST /api/login
user=admin&user=guest&password=test

GET /api/user?id=1&id=2
\`\`\`

### 3. HTTP Method Override
**What to test:**
- Use different HTTP methods
- X-HTTP-Method-Override header
- Method override via form parameters

### 4. Path Traversal in Authentication
**What to test:**
- URL encoding in paths
- Directory traversal sequences
- Case sensitivity bypass

**Examples:**
\`\`\`
/admin/../../api/user
/Admin (case variation)
/admin%2f../user
\`\`\`

### 5. JSON Parameter Injection
**What to test:**
- Array injection in JSON
- Type confusion attacks
- Boolean confusion

**Examples:**
\`\`\`json
{
  "username": ["admin", "guest"],
  "password": "test"
}

{
  "admin": true,
  "username": "guest"
}
\`\`\`

## Testing Methodology
1. Map all authentication mechanisms
2. Identify authentication decision points
3. Test each bypass technique systematically
4. Analyze server responses for inconsistencies
5. Document all findings with proof of concept

## Tools
- Burp Suite - Authentication testing
- OWASP ZAP - Automated scanner
- Custom scripts for specific tests
- Browser developer tools
`,

    "sql-injection": `
# SQL Injection Testing Guide

## Overview
SQL injection occurs when user input is not properly sanitized before being used in SQL queries.

## Types of SQL Injection

### 1. Union-based SQL Injection
**What to test:**
- UNION SELECT statements
- Column number enumeration
- Data extraction via UNION

**Test payloads:**
\`\`\`sql
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT version(),database(),user()--
\`\`\`

### 2. Boolean-based Blind SQL Injection
**What to test:**
- True/false conditions
- Time-based delays
- Character-by-character extraction

**Test payloads:**
\`\`\`sql
' AND 1=1--
' AND 1=2--
' AND (SELECT COUNT(*) FROM users)>0--
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
\`\`\`

### 3. Time-based SQL Injection
**What to test:**
- Database-specific delay functions
- Conditional time delays

**Test payloads:**
\`\`\`sql
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
'; SELECT pg_sleep(5)--
\`\`\`

### 4. Error-based SQL Injection
**What to test:**
- Error message information disclosure
- Database fingerprinting via errors

**Test payloads:**
\`\`\`sql
'
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
\`\`\`

## Testing Methodology
1. Identify input parameters
2. Test for SQL injection points
3. Determine database type and version
4. Extract database schema
5. Extract sensitive data
6. Test for write access and file operations

## Advanced Techniques
- Second-order SQL injection
- Stored procedure injection
- NoSQL injection variants
- ORM injection attacks

## Prevention Testing
- Verify parameterized queries
- Test input validation effectiveness
- Check error handling
- Validate least privilege principles

## Tools
- SQLMap - Automated SQL injection testing
- Burp Suite - Manual testing
- Custom payloads and scripts
- Database-specific tools
`,

    "xss": `
# Cross-Site Scripting (XSS) Testing Guide

## Overview
XSS vulnerabilities allow attackers to inject malicious scripts into web applications.

## Types of XSS

### 1. Reflected XSS
**What to test:**
- URL parameters
- Form inputs
- HTTP headers

**Test payloads:**
\`\`\`html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
\`\`\`

### 2. Stored XSS
**What to test:**
- User profiles
- Comments and reviews
- File uploads
- Database-stored content

**Advanced payloads:**
\`\`\`html
<script>
fetch('/api/admin', {
  method: 'POST',
  body: JSON.stringify({action: 'createUser', role: 'admin'}),
  headers: {'Content-Type': 'application/json'}
});
</script>
\`\`\`

### 3. DOM-based XSS
**What to test:**
- Client-side JavaScript processing
- URL fragments
- PostMessage APIs
- Client-side templating

**Test techniques:**
\`\`\`javascript
location.hash = '<img src=x onerror=alert(1)>'
window.postMessage('<script>alert(1)</script>', '*')
\`\`\`

## Filter Bypass Techniques

### 1. Encoding Bypass
\`\`\`html
&lt;script&gt;alert('XSS')&lt;/script&gt;
%3Cscript%3Ealert('XSS')%3C/script%3E
\u003cscript\u003ealert('XSS')\u003c/script\u003e
\`\`\`

### 2. Case Variation
\`\`\`html
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>
\`\`\`

### 3. Alternative Tags and Events
\`\`\`html
<iframe src=javascript:alert('XSS')>
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
\`\`\`

## Advanced Testing Techniques
- Polyglot payloads
- Context-aware testing
- CSP bypass techniques
- Framework-specific vectors

## Content Security Policy Testing
- Test CSP header effectiveness
- Look for unsafe-inline and unsafe-eval
- Test nonce and hash implementations
- Check for CSP bypass vectors

## Tools
- Burp Suite XSS extensions
- XSSHunter for blind XSS
- DOMPurify testing
- Browser developer tools
- Custom payload generators
`,

    "rate-limiting": `
# Rate Limiting Testing Guide

## Overview
Rate limiting controls how frequently users can make requests to an API to prevent abuse and ensure service availability.

## Rate Limiting Bypass Techniques

### 1. IP Address Manipulation
**What to test:**
- X-Forwarded-For header manipulation
- X-Real-IP header spoofing
- Multiple IP addresses rotation
- IPv4 vs IPv6 variations

**Test headers:**
\`\`\`
X-Forwarded-For: 192.168.1.1
X-Real-IP: 10.0.0.1
X-Originating-IP: 172.16.0.1
X-Remote-IP: 203.0.113.1
X-Remote-Addr: 198.51.100.1
\`\`\`

### 2. User Agent Variation
**What to test:**
- Different user agent strings
- Empty or missing user agents
- Custom user agent values

### 3. Authentication Token Cycling
**What to test:**
- Multiple valid tokens
- Token rotation strategies
- Anonymous vs authenticated limits

### 4. Distributed Requests
**What to test:**
- Multiple concurrent connections
- Request distribution patterns
- Session-based rate limiting

## Testing Methodology

### 1. Identify Rate Limiting Implementation
- Send requests at normal rate
- Gradually increase request frequency
- Identify threshold and time windows
- Analyze error responses and headers

### 2. Bypass Testing
\`\`\`bash
# Test header manipulation
for ip in 192.168.1.{1..100}; do
  curl -H "X-Forwarded-For: $ip" https://api.example.com/endpoint
done

# Test with different user agents
curl -H "User-Agent: Bot1" https://api.example.com/endpoint
curl -H "User-Agent: Bot2" https://api.example.com/endpoint
\`\`\`

### 3. Response Analysis
- Check for rate limit headers
- Analyze HTTP status codes
- Monitor response times
- Look for inconsistent behavior

## Rate Limit Headers to Check
\`\`\`
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1640995200
Retry-After: 60
\`\`\`

## Advanced Testing

### 1. Race Condition Testing
- Send simultaneous requests
- Test for inconsistent counting
- Look for temporary bypass windows

### 2. Algorithm Analysis
- Token bucket vs leaky bucket
- Fixed window vs sliding window
- Per-user vs global limits

### 3. Resource-Specific Testing
- Different endpoints may have different limits
- POST vs GET request limits
- File upload rate limiting

## Tools and Scripts
- Burp Suite Intruder
- Custom rate testing scripts
- Apache Bench (ab)
- wrk load testing tool
- Custom Python/Node.js scripts

## Expected Behaviors
- Consistent rate limit enforcement
- Proper error messages (HTTP 429)
- Informative rate limit headers
- Graceful degradation under load
`
  };

  return guides[topic] || "Guide not found for the specified topic.";
} 