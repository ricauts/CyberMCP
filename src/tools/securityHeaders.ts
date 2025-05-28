import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register security headers testing tools
 */
export function registerSecurityHeaderTools(server: McpServer) {
  // Security headers check tool
  server.tool(
    "security_headers_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      http_method: z.enum(["GET", "POST", "HEAD"]).default("GET").describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, http_method, use_auth }) => {
      try {
        // Get auth headers if available and requested
        let headers = {};
        if (use_auth) {
          const authManager = AuthManager.getInstance();
          const authState = authManager.getAuthState();
          
          if (authState.type !== 'none' && authState.headers) {
            headers = { ...headers, ...authState.headers };
          }
        }
        
        // Make the request
        const response = await axios({
          method: http_method.toLowerCase(),
          url: endpoint,
          headers,
          validateStatus: () => true, // Accept any status code
        });
        
        // Check security headers
        const headerResults = checkSecurityHeaders(response.headers);
        
        // Add authentication info to the report
        const authManager = AuthManager.getInstance();
        const authState = authManager.getAuthState();
        const authInfo = use_auth && authState.type !== 'none'
          ? `\nTest performed with authentication: ${authState.type}`
          : '\nTest performed without authentication';
        
        return {
          content: [
            {
              type: "text",
              text: formatHeaderResults(headerResults, endpoint, authInfo),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error checking security headers: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );

  // CORS configuration check tool
  server.tool(
    "cors_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      origin: z.string().default("https://example.com").describe("Origin to test CORS with"),
      methods: z.array(z.enum(["GET", "POST", "PUT", "DELETE", "OPTIONS"])).default(["GET", "POST"]).describe("HTTP methods to test"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, origin, methods, use_auth }) => {
      try {
        const results = [];
        
        // Get auth headers if available and requested
        let headers = {
          Origin: origin,
        };
        
        if (use_auth) {
          const authManager = AuthManager.getInstance();
          const authState = authManager.getAuthState();
          
          if (authState.type !== 'none' && authState.headers) {
            headers = { ...headers, ...authState.headers };
          }
        }
        
        // Test preflight request
        const preflightResponse = await axios({
          method: 'OPTIONS',
          url: endpoint,
          headers: {
            ...headers,
            'Access-Control-Request-Method': methods.join(','),
            'Access-Control-Request-Headers': 'content-type,authorization',
          },
          validateStatus: () => true,
        });
        
        results.push({
          type: 'Preflight Request',
          status: preflightResponse.status,
          headers: extractCorsHeaders(preflightResponse.headers),
        });
        
        // Test actual requests
        for (const method of methods) {
          const response = await axios({
            method: method,
            url: endpoint,
            headers,
            validateStatus: () => true,
          });
          
          results.push({
            type: `${method} Request`,
            status: response.status,
            headers: extractCorsHeaders(response.headers),
          });
        }
        
        // Add authentication info to the report
        const authManager = AuthManager.getInstance();
        const authState = authManager.getAuthState();
        const authInfo = use_auth && authState.type !== 'none'
          ? `\nTests performed with authentication: ${authState.type}`
          : '\nTests performed without authentication';
        
        return {
          content: [
            {
              type: "text",
              text: formatCorsResults(results, endpoint, origin, authInfo),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error checking CORS configuration: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
}

/**
 * Check security headers in response
 */
function checkSecurityHeaders(headers: Record<string, string>): Array<{
  name: string;
  status: "present" | "missing" | "misconfigured";
  value?: string;
  description: string;
  risk: "high" | "medium" | "low";
  recommendation: string;
}> {
  const results = [];
  const lowercaseHeaders = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
  );
  
  // Content Security Policy
  const csp = lowercaseHeaders['content-security-policy'];
  if (!csp) {
    results.push({
      name: 'Content-Security-Policy',
      status: 'missing',
      description: 'No Content Security Policy header found',
      risk: 'high',
      recommendation: 'Implement a strict Content Security Policy to prevent XSS and other injection attacks',
    });
  } else {
    const cspResult = {
      name: 'Content-Security-Policy',
      status: 'present',
      value: csp,
      description: 'Content Security Policy is configured',
      risk: 'low',
      recommendation: '',
    };
    
    // Check for unsafe CSP directives
    if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
      cspResult.status = 'misconfigured';
      cspResult.risk = 'medium';
      cspResult.description = 'CSP contains unsafe directives';
      cspResult.recommendation = 'Remove unsafe-inline and unsafe-eval directives from CSP';
    } else {
      cspResult.recommendation = 'Monitor and update CSP based on application needs';
    }
    
    results.push(cspResult);
  }
  
  // X-Frame-Options
  const xframe = lowercaseHeaders['x-frame-options'];
  if (!xframe) {
    results.push({
      name: 'X-Frame-Options',
      status: 'missing',
      description: 'No X-Frame-Options header found',
      risk: 'medium',
      recommendation: 'Add X-Frame-Options header to prevent clickjacking attacks',
    });
  } else {
    const xframeResult = {
      name: 'X-Frame-Options',
      status: 'present',
      value: xframe,
      description: 'X-Frame-Options is configured',
      risk: 'low',
      recommendation: '',
    };
    
    if (xframe.toLowerCase() === 'allow') {
      xframeResult.status = 'misconfigured';
      xframeResult.risk = 'medium';
      xframeResult.description = 'X-Frame-Options allows framing';
      xframeResult.recommendation = 'Change X-Frame-Options to DENY or SAMEORIGIN';
    } else {
      xframeResult.recommendation = 'Current configuration is secure';
    }
    
    results.push(xframeResult);
  }
  
  // X-Content-Type-Options
  const xcto = lowercaseHeaders['x-content-type-options'];
  if (!xcto) {
    results.push({
      name: 'X-Content-Type-Options',
      status: 'missing',
      description: 'No X-Content-Type-Options header found',
      risk: 'medium',
      recommendation: 'Add X-Content-Type-Options: nosniff header',
    });
  } else {
    results.push({
      name: 'X-Content-Type-Options',
      status: 'present',
      value: xcto,
      description: 'X-Content-Type-Options is configured',
      risk: 'low',
      recommendation: 'Current configuration is secure',
    });
  }
  
  // Strict-Transport-Security
  const hsts = lowercaseHeaders['strict-transport-security'];
  if (!hsts) {
    results.push({
      name: 'Strict-Transport-Security',
      status: 'missing',
      description: 'No HSTS header found',
      risk: 'high',
      recommendation: 'Add Strict-Transport-Security header with appropriate max-age',
    });
  } else {
    const hstsResult = {
      name: 'Strict-Transport-Security',
      status: 'present',
      value: hsts,
      description: 'HSTS is configured',
      risk: 'low',
      recommendation: '',
    };
    
    const maxAge = parseInt(hsts.match(/max-age=([0-9]+)/)?.[1] || '0');
    if (maxAge < 31536000) { // Less than 1 year
      hstsResult.status = 'misconfigured';
      hstsResult.risk = 'medium';
      hstsResult.description = 'HSTS max-age is too short';
      hstsResult.recommendation = 'Increase HSTS max-age to at least one year (31536000 seconds)';
    } else {
      hstsResult.recommendation = 'Current configuration is secure';
    }
    
    results.push(hstsResult);
  }
  
  // X-XSS-Protection
  const xss = lowercaseHeaders['x-xss-protection'];
  if (!xss) {
    results.push({
      name: 'X-XSS-Protection',
      status: 'missing',
      description: 'No X-XSS-Protection header found',
      risk: 'low',
      recommendation: 'Add X-XSS-Protection: 1; mode=block header',
    });
  } else {
    const xssResult = {
      name: 'X-XSS-Protection',
      status: 'present',
      value: xss,
      description: 'X-XSS-Protection is configured',
      risk: 'low',
      recommendation: '',
    };
    
    if (xss === '0') {
      xssResult.status = 'misconfigured';
      xssResult.risk = 'medium';
      xssResult.description = 'X-XSS-Protection is disabled';
      xssResult.recommendation = 'Enable X-XSS-Protection with mode=block';
    } else {
      xssResult.recommendation = 'Current configuration is secure';
    }
    
    results.push(xssResult);
  }
  
  // Referrer-Policy
  const referrer = lowercaseHeaders['referrer-policy'];
  if (!referrer) {
    results.push({
      name: 'Referrer-Policy',
      status: 'missing',
      description: 'No Referrer-Policy header found',
      risk: 'low',
      recommendation: 'Add Referrer-Policy header with appropriate policy',
    });
  } else {
    results.push({
      name: 'Referrer-Policy',
      status: 'present',
      value: referrer,
      description: 'Referrer-Policy is configured',
      risk: 'low',
      recommendation: 'Current configuration is acceptable',
    });
  }
  
  // Feature-Policy/Permissions-Policy
  const featurePolicy = lowercaseHeaders['feature-policy'] || lowercaseHeaders['permissions-policy'];
  if (!featurePolicy) {
    results.push({
      name: 'Permissions-Policy',
      status: 'missing',
      description: 'No Permissions-Policy header found',
      risk: 'low',
      recommendation: 'Consider adding Permissions-Policy header to control browser features',
    });
  } else {
    results.push({
      name: 'Permissions-Policy',
      status: 'present',
      value: featurePolicy,
      description: 'Permissions-Policy is configured',
      risk: 'low',
      recommendation: 'Review and update policies based on application needs',
    });
  }
  
  return results;
}

/**
 * Extract CORS-related headers from response
 */
function extractCorsHeaders(headers: Record<string, string>): Record<string, string> {
  const corsHeaders: Record<string, string> = {};
  const lowercaseHeaders = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
  );
  
  const relevantHeaders = [
    'access-control-allow-origin',
    'access-control-allow-methods',
    'access-control-allow-headers',
    'access-control-allow-credentials',
    'access-control-expose-headers',
    'access-control-max-age',
    'vary',
  ];
  
  for (const header of relevantHeaders) {
    if (lowercaseHeaders[header]) {
      corsHeaders[header] = lowercaseHeaders[header];
    }
  }
  
  return corsHeaders;
}

/**
 * Format security headers check results into a readable report
 */
function formatHeaderResults(
  results: Array<{
    name: string;
    status: string;
    value?: string;
    description: string;
    risk: string;
    recommendation: string;
  }>,
  endpoint: string,
  authInfo: string = ''
): string {
  let report = `# Security Headers Analysis for ${endpoint}${authInfo}\n\n`;
  
  // Group findings by risk level
  const highRisk = results.filter(r => r.risk === 'high');
  const mediumRisk = results.filter(r => r.risk === 'medium');
  const lowRisk = results.filter(r => r.risk === 'low');
  
  // Add summary
  report += `## Summary\n\n`;
  report += `- High Risk Issues: ${highRisk.length}\n`;
  report += `- Medium Risk Issues: ${mediumRisk.length}\n`;
  report += `- Low Risk Issues: ${lowRisk.length}\n\n`;
  
  // Add detailed findings
  if (highRisk.length > 0) {
    report += `## High Risk Findings\n\n`;
    for (const finding of highRisk) {
      report += formatFinding(finding);
    }
  }
  
  if (mediumRisk.length > 0) {
    report += `## Medium Risk Findings\n\n`;
    for (const finding of mediumRisk) {
      report += formatFinding(finding);
    }
  }
  
  if (lowRisk.length > 0) {
    report += `## Low Risk Findings\n\n`;
    for (const finding of lowRisk) {
      report += formatFinding(finding);
    }
  }
  
  // Add general recommendations
  report += `## General Recommendations\n\n`;
  report += `- Regularly review and update security headers\n`;
  report += `- Use security header scanning tools in CI/CD pipeline\n`;
  report += `- Keep informed about new security headers and best practices\n`;
  report += `- Consider implementing additional security headers based on application needs\n`;
  
  return report;
}

/**
 * Format CORS check results into a readable report
 */
function formatCorsResults(
  results: Array<{
    type: string;
    status: number;
    headers: Record<string, string>;
  }>,
  endpoint: string,
  origin: string,
  authInfo: string = ''
): string {
  let report = `# CORS Configuration Analysis for ${endpoint}${authInfo}\n\n`;
  
  // Add test information
  report += `## Test Information\n\n`;
  report += `- Tested Origin: ${origin}\n`;
  report += `- Number of Tests: ${results.length}\n\n`;
  
  // Add detailed results
  report += `## Detailed Results\n\n`;
  
  for (const result of results) {
    report += `### ${result.type}\n`;
    report += `- Status Code: ${result.status}\n`;
    report += `- CORS Headers:\n`;
    
    if (Object.keys(result.headers).length === 0) {
      report += `  * No CORS headers found\n`;
    } else {
      for (const [header, value] of Object.entries(result.headers)) {
        report += `  * ${header}: ${value}\n`;
      }
    }
    report += "\n";
  }
  
  // Add analysis
  report += `## Analysis\n\n`;
  
  // Check for common issues
  const issues = [];
  const preflight = results.find(r => r.type === 'Preflight Request');
  
  if (preflight) {
    const allowOrigin = preflight.headers['access-control-allow-origin'];
    if (allowOrigin === '*') {
      issues.push('CORS allows requests from any origin (*)');
    }
    
    if (!preflight.headers['access-control-allow-methods']) {
      issues.push('No explicit allowed methods specified');
    }
    
    if (preflight.headers['access-control-allow-credentials'] === 'true' && allowOrigin === '*') {
      issues.push('Allowing credentials with wildcard origin is not secure');
    }
  }
  
  if (issues.length > 0) {
    report += `### Issues Found\n\n`;
    for (const issue of issues) {
      report += `- ${issue}\n`;
    }
    report += "\n";
  }
  
  // Add recommendations
  report += `## Recommendations\n\n`;
  
  if (issues.length > 0) {
    report += `- Restrict CORS to specific trusted origins\n`;
    report += `- Explicitly specify allowed methods and headers\n`;
    report += `- Use appropriate credentials mode\n`;
    report += `- Consider implementing rate limiting for CORS requests\n`;
  } else {
    report += `- Monitor CORS configuration for changes\n`;
    report += `- Regularly review allowed origins\n`;
    report += `- Keep CORS configuration as restrictive as possible\n`;
  }
  
  return report;
}

/**
 * Format a single security header finding
 */
function formatFinding(finding: {
  name: string;
  status: string;
  value?: string;
  description: string;
  risk: string;
  recommendation: string;
}): string {
  let text = `### ${finding.name}\n`;
  text += `- Status: ${finding.status}\n`;
  if (finding.value) {
    text += `- Current Value: ${finding.value}\n`;
  }
  text += `- Description: ${finding.description}\n`;
  text += `- Risk Level: ${finding.risk}\n`;
  text += `- Recommendation: ${finding.recommendation}\n\n`;
  return text;
}