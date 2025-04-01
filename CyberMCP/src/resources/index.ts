import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * Register all resources with the MCP server
 */
export function registerResources(server: McpServer) {
  // Register cybersecurity checklists resource
  server.resource(
    "cybersecurity_checklists",
    new ResourceTemplate("cybersecurity://checklists/{category}", { list: "cybersecurity://checklists" }),
    async (uri, { category }) => {
      const checklists = getChecklist(category);
      
      return {
        contents: [{
          uri: uri.href,
          text: checklists,
        }]
      };
    }
  );

  // Register API testing guide resource
  server.resource(
    "testing_guides",
    new ResourceTemplate("guides://api-testing/{topic}", { list: "guides://api-testing" }),
    async (uri, { topic }) => {
      const guide = getGuide(topic);
      
      return {
        contents: [{
          uri: uri.href,
          text: guide,
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

## Understanding JWT
JSON Web Tokens (JWT) consist of three parts: header, payload, and signature. Each security test should examine all three components.

## Common Vulnerabilities
1. **Algorithm None Attack**: Some JWT libraries accept tokens with the "alg" set to "none"
2. **Weak Signature**: Use of weak keys or algorithms
3. **Missing Claims**: Absence of important claims like 'exp', 'iat', 'nbf'
4. **Information Disclosure**: Sensitive information stored in the payload
5. **Brute Force Attacks**: Weak secrets vulnerable to brute forcing

## Testing Methodology
1. Decode the JWT and examine its structure
2. Check if the "alg" parameter can be manipulated
3. Test for token expiration validation
4. Attempt to modify the payload without changing the signature
5. Check for signature validation bypass

## Remediation
1. Use strong algorithms (RS256, ES256)
2. Include all necessary claims
3. Set appropriate expiration times
4. Validate all parts of the token
5. Use strong, unique secrets for each application
`,

    "auth-bypass": `
# Authentication Bypass Testing Guide

## Understanding Authentication Bypass
Authentication bypass occurs when an attacker can access protected resources without proper authentication.

## Common Vulnerabilities
1. **Missing Authentication**: Endpoints failing to verify authentication
2. **Insecure Direct Object References**: Accessing resources by changing identifiers
3. **Session Fixation**: Forcing a user to use a known session ID
4. **Broken Authentication Logic**: Flaws in authentication workflows

## Testing Methodology
1. Remove authentication tokens and attempt access
2. Manipulate session identifiers
3. Try accessing resources with IDs of other users
4. Test for logic flaws in authentication workflows
5. Check for session timeout enforcement

## Remediation
1. Implement consistent authentication checks
2. Use proper session management
3. Implement proper authorization checks
4. Use indirect object references
5. Enforce proper authentication workflows
`,

    "sql-injection": `
# SQL Injection Testing Guide

## Understanding SQL Injection
SQL injection occurs when untrusted user input is directly used in SQL queries.

## Common Vulnerabilities
1. **Classic SQL Injection**: Direct insertion of SQL code
2. **Blind SQL Injection**: No direct output but observable behavior
3. **Time-Based SQL Injection**: Using time delays to infer results
4. **Error-Based SQL Injection**: Using error messages to extract data

## Testing Methodology
1. Test with single quotes and SQL commands
2. Look for error messages that reveal database information
3. Test for blind injection using boolean conditions
4. Test for time-based injection using sleep/delay functions
5. Test for stacked queries using semicolons

## Remediation
1. Use parameterized queries or prepared statements
2. Implement input validation and sanitization
3. Apply least privilege principle to database accounts
4. Use ORM frameworks properly
5. Implement proper error handling
`,

    "xss": `
# Cross-Site Scripting (XSS) Testing Guide for APIs

## Understanding XSS in APIs
While traditional XSS affects web pages, APIs can still be vulnerable if they return user-supplied data that gets rendered in a browser.

## Common Vulnerabilities
1. **Reflected XSS**: User input is returned in API responses without sanitization
2. **Stored XSS**: Malicious data is stored and later returned to other users
3. **DOM-Based XSS**: Client-side code processes API data insecurely

## Testing Methodology
1. Submit JS payloads in all API parameters
2. Check if payloads are returned unencoded in responses
3. Test different contexts (HTML, JSON, XML)
4. Check content-type headers and their enforcement
5. Test different encoding schemes

## Remediation
1. Apply proper encoding based on the context
2. Implement Content-Security-Policy headers
3. Use JSON serialization for API responses
4. Set proper content-type headers
5. Implement input validation and sanitization
`,

    "rate-limiting": `
# API Rate Limiting Testing Guide

## Understanding Rate Limiting
Rate limiting protects APIs from abuse, DoS attacks, and resource exhaustion.

## Common Vulnerabilities
1. **Missing Rate Limits**: No restrictions on request frequency
2. **Per-Endpoint Bypass**: Limits applied inconsistently across endpoints
3. **Distributed Attacks**: Attacks from multiple sources
4. **Account Enumeration**: Using rate limit errors to identify valid accounts

## Testing Methodology
1. Make rapid, repeated requests to endpoints
2. Test different authentication states (anonymous vs. authenticated)
3. Distribute requests across different IPs or accounts
4. Check for informative rate limit headers
5. Test bypasses using different parameters or methods

## Remediation
1. Implement consistent rate limiting
2. Use token bucket or leaky bucket algorithms
3. Apply rate limits based on multiple factors (IP, user, endpoint)
4. Return standard 429 responses with clear headers
5. Implement progressive penalties for abuse
`,
  };

  return guides[topic] || "Guide not found for the specified topic.";
} 