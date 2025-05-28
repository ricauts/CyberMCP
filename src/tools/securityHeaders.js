import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register security headers testing tools
 */
export function registerSecurityHeadersTools(server) {
  // Security headers check
  server.tool(
    "security_headers_check",
    {
      endpoint: server.zod.string().url().describe("API endpoint to test"),
      http_method: server.zod.enum(["GET", "HEAD", "OPTIONS"]).default("GET").describe("HTTP method to use"),
      use_auth: server.zod.boolean().default(true).describe("Whether to use current authentication if available"),
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
        
        // Get headers (case insensitive)
        const responseHeaders = response.headers;
        const headerMap = new Map();
        
        for (const key in responseHeaders) {
          headerMap.set(key.toLowerCase(), responseHeaders[key]);
        }
        
        // Check for security headers
        const securityHeaders = checkSecurityHeaders(headerMap);
        
        // Generate recommendations
        const recommendations = generateRecommendations(securityHeaders);
        
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
              text: formatSecurityHeadersReport(securityHeaders, recommendations, endpoint, authInfo),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error checking security headers: ${error.message}`,
            },
          ],
        };
      }
    }
  );
}

/**
 * Check for security headers in response
 */
function checkSecurityHeaders(headers) {
  return [
    {
      name: "Strict-Transport-Security",
      present: headers.has("strict-transport-security"),
      value: headers.get("strict-transport-security") || "",
      description: "Ensures the browser only uses HTTPS for the domain",
      severity: "High",
      recommendation: headers.has("strict-transport-security") 
        ? (headers.get("strict-transport-security")?.includes("max-age=31536000") 
            ? "Good: HSTS is properly configured"
            : "Improve: Set max-age to at least one year (31536000)")
        : "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
      name: "Content-Security-Policy",
      present: headers.has("content-security-policy"),
      value: headers.get("content-security-policy") || "",
      description: "Controls which resources the browser is allowed to load",
      severity: "High",
      recommendation: headers.has("content-security-policy")
        ? "Verify that the CSP policy is restrictive enough for your application"
        : "Add a Content-Security-Policy header appropriate for your application",
    },
    {
      name: "X-Content-Type-Options",
      present: headers.has("x-content-type-options"),
      value: headers.get("x-content-type-options") || "",
      description: "Prevents the browser from MIME-sniffing content types",
      severity: "Medium",
      recommendation: headers.has("x-content-type-options") 
        ? (headers.get("x-content-type-options") === "nosniff" 
            ? "Good: X-Content-Type-Options is properly configured" 
            : "Fix: Set X-Content-Type-Options to 'nosniff'")
        : "Add: X-Content-Type-Options: nosniff",
    },
    {
      name: "X-Frame-Options",
      present: headers.has("x-frame-options"),
      value: headers.get("x-frame-options") || "",
      description: "Prevents your site from being embedded in iframes on other sites",
      severity: "Medium",
      recommendation: headers.has("x-frame-options")
        ? (["DENY", "SAMEORIGIN"].includes(headers.get("x-frame-options")?.toUpperCase() || "") 
            ? "Good: X-Frame-Options is properly configured" 
            : "Fix: Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'")
        : "Add: X-Frame-Options: DENY",
    },
    {
      name: "X-XSS-Protection",
      present: headers.has("x-xss-protection"),
      value: headers.get("x-xss-protection") || "",
      description: "Enables browser's built-in XSS filtering",
      severity: "Low",
      recommendation: headers.has("x-xss-protection")
        ? (headers.get("x-xss-protection") === "1; mode=block" 
            ? "Good: X-XSS-Protection is properly configured" 
            : "Improve: Set X-XSS-Protection to '1; mode=block'")
        : "Add: X-XSS-Protection: 1; mode=block",
    },
    {
      name: "Referrer-Policy",
      present: headers.has("referrer-policy"),
      value: headers.get("referrer-policy") || "",
      description: "Controls how much referrer information is included with requests",
      severity: "Medium",
      recommendation: headers.has("referrer-policy")
        ? "Verify that the referrer policy is appropriate for your application"
        : "Add a Referrer-Policy header (e.g., 'strict-origin-when-cross-origin')",
    },
    {
      name: "Cache-Control",
      present: headers.has("cache-control"),
      value: headers.get("cache-control") || "",
      description: "Controls how responses are cached",
      severity: "Medium",
      recommendation: headers.has("cache-control")
        ? (headers.get("cache-control")?.includes("no-store") 
            ? "Good: Cache-Control prevents storage of sensitive data" 
            : "Consider: For sensitive data, use 'Cache-Control: no-store'")
        : "Add appropriate Cache-Control header based on content sensitivity",
    },
    {
      name: "Access-Control-Allow-Origin",
      present: headers.has("access-control-allow-origin"),
      value: headers.get("access-control-allow-origin") || "",
      description: "Controls which domains can access the API via CORS",
      severity: "High",
      recommendation: headers.has("access-control-allow-origin")
        ? (headers.get("access-control-allow-origin") === "*" 
            ? "Warning: CORS is enabled for all origins" 
            : "Verify that CORS is correctly configured for your use case")
        : "CORS not enabled - appropriate if this API should not be accessed cross-origin",
    },
  ];
}

/**
 * Generate overall recommendations based on security headers
 */
function generateRecommendations(securityHeaders) {
  const recommendations = [];
  
  // Count missing headers by severity
  const missingHigh = securityHeaders.filter(h => !h.present && h.severity === "High").length;
  const missingMedium = securityHeaders.filter(h => !h.present && h.severity === "Medium").length;
  const missingLow = securityHeaders.filter(h => !h.present && h.severity === "Low").length;
  
  // Overall security assessment
  if (missingHigh > 0) {
    recommendations.push(`Critical security headers are missing. Add the ${missingHigh} missing high-priority headers first.`);
  }
  
  if (missingMedium > 0) {
    recommendations.push(`Improve security by adding the ${missingMedium} missing medium-priority headers.`);
  }
  
  if (missingLow > 0) {
    recommendations.push(`Consider adding the ${missingLow} missing low-priority headers for best practices.`);
  }
  
  // HTTPS enforcement
  if (!securityHeaders.find(h => h.name === "Strict-Transport-Security")?.present) {
    recommendations.push("Enforce HTTPS by implementing HSTS (HTTP Strict Transport Security).");
  }
  
  // XSS protection
  if (!securityHeaders.find(h => h.name === "Content-Security-Policy")?.present) {
    recommendations.push("Implement Content-Security-Policy to prevent XSS attacks.");
  }
  
  // General advice
  recommendations.push("Consider using a security headers scanner like securityheaders.com to regularly audit your site.");
  
  return recommendations;
}

/**
 * Format security headers results into a readable report
 */
function formatSecurityHeadersReport(
  securityHeaders,
  recommendations,
  endpoint,
  authInfo = ''
) {
  let report = `# Security Headers Analysis for ${endpoint}${authInfo}\n\n`;
  
  // Overall score
  const totalHeaders = securityHeaders.length;
  const presentHeaders = securityHeaders.filter(h => h.present).length;
  const score = Math.round((presentHeaders / totalHeaders) * 100);
  
  report += `## Summary\n\n`;
  report += `- Security Score: ${score}% (${presentHeaders}/${totalHeaders} headers present)\n`;
  report += `- Missing Security Headers: ${totalHeaders - presentHeaders}\n\n`;
  
  // Headers table
  report += `## Security Headers\n\n`;
  
  // Group by severity
  for (const severity of ["High", "Medium", "Low"]) {
    report += `### ${severity} Priority\n\n`;
    
    const filteredHeaders = securityHeaders.filter(h => h.severity === severity);
    
    for (const header of filteredHeaders) {
      report += `#### ${header.name}\n`;
      report += `- Present: ${header.present ? "✅ Yes" : "❌ No"}\n`;
      
      if (header.present && header.value) {
        report += `- Value: \`${header.value}\`\n`;
      }
      
      report += `- Description: ${header.description}\n`;
      report += `- Recommendation: ${header.recommendation}\n\n`;
    }
  }
  
  // Recommendations
  report += `## Overall Recommendations\n\n`;
  
  for (const recommendation of recommendations) {
    report += `- ${recommendation}\n`;
  }
  
  report += `\n## Best Practices\n\n`;
  report += `1. Regularly audit security headers\n`;
  report += `2. Keep headers up to date with evolving security standards\n`;
  report += `3. Test headers in all environments (development, staging, production)\n`;
  report += `4. Use appropriate security headers based on your application's needs\n`;
  report += `5. Balance security with functionality - overly restrictive headers can break features\n`;
  
  return report;
}