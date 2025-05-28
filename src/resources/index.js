import { z } from "zod";

/**
 * Register security resources
 */
export function registerResources(server) {
  // Register security checklists
  server.resource({
    uriPattern: "cybersecurity://checklists/{category}",
    parameters: {
      category: z.enum(["authentication", "injection", "data_leakage", "rate_limiting", "general"]),
    },
    handler: ({ category }) => {
      return {
        content: [
          {
            type: "text",
            text: getChecklistForCategory(category),
          },
        ],
      };
    },
  });
  
  // Register security guides
  server.resource({
    uriPattern: "guides://api-testing/{topic}",
    parameters: {
      topic: z.enum(["jwt-testing", "auth-bypass", "sql-injection", "xss", "rate-limiting"]),
    },
    handler: ({ topic }) => {
      return {
        content: [
          {
            type: "text",
            text: getGuideForTopic(topic),
          },
        ],
      };
    },
  });
}

/**
 * Get security checklist by category
 */
function getChecklistForCategory(category) {
  const checklists = {
    "authentication": "# API Authentication Security Checklist\n\n## Authentication Mechanisms\n- [ ] Implement proper token-based authentication (JWT, OAuth)\n- [ ] Use HTTPS for all authentication traffic\n- [ ] Implement proper password hashing (bcrypt, Argon2)\n- [ ] Enforce strong password policies\n- [ ] Implement account lockout after failed login attempts\n- [ ] Use secure session management\n- [ ] Implement MFA where appropriate\n\n## Token Security\n- [ ] Set reasonable token expiration times\n- [ ] Implement token revocation\n- [ ] Store tokens securely on client side\n- [ ] Validate token signature and claims\n- [ ] Use appropriate signing algorithm (RS256 vs HS256)\n\n## API Protection\n- [ ] Protect all sensitive endpoints with authentication\n- [ ] Implement proper role-based access control\n- [ ] Validate authentication on every request\n- [ ] Implement rate limiting\n- [ ] Use secure headers (X-Content-Type-Options, HSTS)\n- [ ] Implement CSRF protection for cookie-based auth",
    
    "injection": "# API Injection Vulnerabilities Checklist\n\n## SQL Injection\n- [ ] Use parameterized queries or prepared statements\n- [ ] Implement input validation and sanitization\n- [ ] Use ORM with proper configuration\n- [ ] Use principle of least privilege for database accounts\n- [ ] Implement database activity monitoring\n\n## NoSQL Injection\n- [ ] Validate and sanitize all input for NoSQL queries\n- [ ] Use typed queries instead of string concatenation\n- [ ] Escape input used in NoSQL operations\n\n## Command Injection\n- [ ] Avoid using system commands with user input\n- [ ] Use allowlists for permitted commands\n- [ ] Sanitize and validate all input used in system calls\n\n## XSS (for API responses consumed by browsers)\n- [ ] Sanitize output data, especially for APIs serving web clients\n- [ ] Set proper Content-Type headers\n- [ ] Implement Content-Security-Policy headers\n- [ ] Use secure response encoding",
    
    "data_leakage": "# API Data Leakage Prevention Checklist\n\n## Sensitive Data Exposure\n- [ ] Identify and classify all sensitive data\n- [ ] Encrypt sensitive data at rest and in transit\n- [ ] Implement field-level security\n- [ ] Mask or truncate sensitive data in responses\n- [ ] Implement proper error handling\n\n## Error Handling\n- [ ] Use generic error messages in production\n- [ ] Implement structured error responses\n- [ ] Prevent stack traces from being returned to clients\n- [ ] Log detailed errors server-side only\n\n## Information Disclosure\n- [ ] Disable directory listing\n- [ ] Remove technical details from HTTP headers\n- [ ] Implement proper CORS policy\n- [ ] Protect internal endpoints and documentation\n- [ ] Disable unnecessary HTTP methods\n\n## Data Protection\n- [ ] Implement proper data retention policies\n- [ ] Use secure deletion practices\n- [ ] Implement logging and monitoring for data access\n- [ ] Protect API specifications and documentation",
    
    "rate_limiting": "# API Rate Limiting Checklist\n\n## Implementation\n- [ ] Set appropriate rate limits for different endpoints\n- [ ] Implement different limits for authenticated vs unauthenticated users\n- [ ] Use token bucket or leaky bucket algorithms\n- [ ] Implement proper response headers (RateLimit-*)\n- [ ] Return proper status codes (429 Too Many Requests)\n\n## Protection Measures\n- [ ] Implement IP-based rate limiting\n- [ ] Implement user-based rate limiting\n- [ ] Set limits for account creation and authentication attempts\n- [ ] Implement API keys for external consumers\n- [ ] Monitor for abnormal traffic patterns\n\n## Response Design\n- [ ] Include retry-after header in rate limit responses\n- [ ] Provide clear error messages for rate limited requests\n- [ ] Include current limit and remaining requests in responses\n- [ ] Implement exponential backoff for repeated violations\n\n## Infrastructure\n- [ ] Implement distributed rate limiting for load-balanced environments\n- [ ] Use Redis or similar for rate limit tracking\n- [ ] Configure CDN or API gateway rate limiting\n- [ ] Implement circuit breakers for critical services",
    
    "general": "# General API Security Checklist\n\n## Infrastructure\n- [ ] Use HTTPS only\n- [ ] Implement proper TLS configuration\n- [ ] Use security headers\n- [ ] Implement WAF protection\n- [ ] Use secure network configurations\n\n## Authentication & Authorization\n- [ ] Implement proper authentication mechanism\n- [ ] Implement role-based access control\n- [ ] Validate authentication on every request\n- [ ] Use proper session management\n\n## Input/Output Handling\n- [ ] Validate all input parameters\n- [ ] Sanitize all outputs\n- [ ] Implement proper error handling\n- [ ] Prevent injection attacks\n\n## API Design\n- [ ] Follow the principle of least privilege\n- [ ] Implement proper versioning\n- [ ] Use appropriate HTTP methods\n- [ ] Implement proper status codes\n\n## Monitoring & Logging\n- [ ] Log all security events\n- [ ] Implement proper audit trails\n- [ ] Set up alerts for suspicious activity\n- [ ] Monitor for vulnerabilities in dependencies\n\n## Response Protection\n- [ ] Implement rate limiting\n- [ ] Protect against OWASP Top 10\n- [ ] Implement proper CORS policy\n- [ ] Secure API documentation"
  };
  
  return checklists[category] || "Checklist not found for the specified category.";
}

/**
 * Get security guide by topic
 */
function getGuideForTopic(topic) {
  const guides = {
    "jwt-testing": "# JWT Security Testing Guide\n\n## Introduction\nJSON Web Tokens (JWT) are commonly used for authentication and secure information exchange. This guide outlines methods to test JWT implementation security.\n\n## Testing Methodology\n\n### 1. Inspect the JWT Structure\nA JWT consists of three parts: header, payload, and signature. Use the \`jwt_vulnerability_check\` tool to analyze these components.\n\n### 2. Check Algorithm Security\n- Test for \"none\" algorithm acceptance\n- Verify algorithm confusion vulnerability (switching RS256 to HS256)\n- Check for weak signing keys\n\n### 3. Validate Token Claims\n- Verify expiration (exp) claim is properly enforced\n- Check if issued at (iat) claim is validated\n- Test audience (aud) and issuer (iss) validation\n\n### 4. Test Token Handling\n- Check for token reuse after logout\n- Test token revocation mechanisms\n- Verify handling of expired tokens\n\n## Security Recommendations\n- Use strong algorithms (RS256, ES256)\n- Implement proper claim validation\n- Set reasonable expiration times\n- Validate token on every request\n- Implement refresh token rotation\n\n## Example Attack Scenarios\n1. Signature bypass using \"none\" algorithm\n2. Token forgery via algorithm confusion\n3. Expired token manipulation\n4. Missing claim exploitation",
    
    "auth-bypass": "# Authentication Bypass Testing Guide\n\n## Introduction\nAuthentication bypass vulnerabilities allow attackers to access protected resources without proper authentication. This guide outlines methods to test for auth bypass issues.\n\n## Testing Methodology\n\n### 1. Direct Resource Access\n- Try accessing protected endpoints directly\n- Test URL manipulation to bypass authentication checks\n- Use the \`auth_bypass_check\` tool to automate testing\n\n### 2. Authentication Header Manipulation\n- Remove authentication headers\n- Use invalid/expired tokens\n- Test with manipulated tokens\n\n### 3. Logic Flaw Testing\n- Test password reset functionality\n- Check for insecure direct object references\n- Test multi-step authentication processes\n\n### 4. Session Management Testing\n- Test session fixation vulnerabilities\n- Check for insecure session handling\n- Test concurrent session limitations\n\n## Security Recommendations\n- Implement consistent authentication checks\n- Use proper session management\n- Implement multi-factor authentication\n- Apply principle of complete mediation\n- Validate authentication on server side\n\n## Example Attack Scenarios\n1. Direct API endpoint access bypass\n2. Token manipulation to gain unauthorized access\n3. Logic flaws in multi-step authentication\n4. Session hijacking due to insecure management",
    
    "sql-injection": "# SQL Injection Testing Guide\n\n## Introduction\nSQL injection allows attackers to manipulate database queries, potentially gaining unauthorized access to data. Use the \`sql_injection_check\` tool to test your API endpoints.\n\n## Testing Methodology\n\n### 1. Identify Vulnerable Parameters\n- Test all input parameters, especially those used for database operations\n- Look for parameters like id, search, filter, sort, etc.\n\n### 2. Test Basic SQL Injection Patterns\n- Use single quotes, double quotes, and comments\n- Test for numeric injections\n- Use the \`sql_injection_check\` tool with different payloads\n\n### 3. Analyze Responses\n- Look for database error messages\n- Check for differences in response times\n- Analyze structural changes in responses\n\n### 4. Advanced Testing\n- Test for blind SQL injection\n- Try union-based injections\n- Check for second-order injections\n\n## Security Recommendations\n- Use parameterized queries\n- Implement input validation\n- Apply proper error handling\n- Use ORM with security in mind\n- Apply principle of least privilege\n\n## Example Attack Scenarios\n1. Basic authentication bypass (OR 1=1)\n2. Data extraction using UNION attacks\n3. Blind SQL injection via response timing\n4. Second-order injection via stored data",
    
    "xss": "# Cross-Site Scripting (XSS) Testing Guide\n\n## Introduction\nWhile APIs aren't typically vulnerable to XSS in the same way web applications are, APIs that return user-generated content to web clients can introduce XSS vulnerabilities. Use the \`xss_check\` tool to test your endpoints.\n\n## Testing Methodology\n\n### 1. Identify Output Contexts\n- Test endpoints that return data to web clients\n- Identify parameters that accept user input\n- Check for HTML/JavaScript contexts in responses\n\n### 2. Test Reflection Points\n- Inject script tags, event handlers, and JavaScript URIs\n- Test HTML attribute contexts\n- Check JSON responses used in innerHTML or eval()\n\n### 3. Analyze Response Encoding\n- Check for proper HTML encoding\n- Verify JSON encoding\n- Test Content-Type headers\n\n### 4. Check Security Headers\n- Verify Content-Security-Policy implementation\n- Check X-XSS-Protection header\n- Test X-Content-Type-Options configuration\n\n## Security Recommendations\n- Sanitize or encode all output\n- Implement proper Content-Type headers\n- Use Content-Security-Policy\n- Validate input data\n- Implement JSON serialization security\n\n## Example Attack Scenarios\n1. Script injection via API response rendered in web client\n2. Event handler injection in HTML attributes\n3. JSON response manipulation leading to client-side injection\n4. DOM-based XSS via insecure API data handling",
    
    "rate-limiting": "# API Rate Limiting Testing Guide\n\n## Introduction\nProper rate limiting prevents abuse, DoS attacks, and resource exhaustion. This guide outlines methods to test rate limiting implementation.\n\n## Testing Methodology\n\n### 1. Baseline Testing\n- Determine normal request patterns\n- Identify API rate limits\n- Test for rate limit headers\n\n### 2. Basic Rate Limit Testing\n- Make rapid sequential requests\n- Verify if limits are enforced\n- Check for 429 status codes\n\n### 3. Bypass Testing\n- Use different IP addresses or proxies\n- Modify user identifiers\n- Test with multiple API keys/tokens\n\n### 4. Distributed Testing\n- Test from multiple sources simultaneously\n- Check for distributed rate limiting\n- Test for timing attacks\n\n## Security Recommendations\n- Implement consistent rate limiting\n- Use multiple limit identifiers (IP, user, token)\n- Implement progressive rate limiting\n- Add proper rate limit headers\n- Track and alert on limit violations\n\n## Example Attack Scenarios\n1. Brute force attacks on authentication endpoints\n2. Resource exhaustion via rapid API requests\n3. Bypass attempts using multiple identities\n4. Distributed attacks from multiple sources"
  };
  
  return guides[topic] || "Guide not found for the specified topic.";
}
