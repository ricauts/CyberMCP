import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register data leakage security testing tools
 */
export function registerDataLeakageTools(server: McpServer) {
  // Test for sensitive data exposure
  server.tool(
    "sensitive_data_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      http_method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("GET").describe("HTTP method to use"),
      request_body: z.string().optional().describe("Request body (for POST/PUT requests)"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, http_method, request_body, use_auth }) => {
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
          data: request_body ? JSON.parse(request_body) : undefined,
          headers,
          validateStatus: () => true, // Accept any status code
        });

        // Check for data leakage in the response
        const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        const responseHeaders = response.headers;
        
        // Patterns to check for in the response
        const sensitivePatterns = [
          // PII
          { type: "Email Address", regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
          { type: "Phone Number", regex: /(\+\d{1,3}[- ]?)?\d{3}[- ]?\d{3,4}[- ]?\d{4}/g },
          { type: "Social Security Number", regex: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g },
          
          // Credentials and Tokens
          { type: "API Key", regex: /(api[_-]?key|apikey|access[_-]?key|auth[_-]?key)[\"']?\s*[=:]\s*[\"']?([a-zA-Z0-9]{16,})/gi },
          { type: "JWT", regex: /eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}/g },
          { type: "Password", regex: /(password|passwd|pwd)[\"']?\s*[=:]\s*[\"']?([^\"']{3,})/gi },
          
          // Internal Info
          { type: "Internal Path", regex: /(\/var\/www\/|\/home\/\w+\/|C:\\Program Files\\|C:\\inetpub\\)/gi },
          { type: "SQL Query", regex: /(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s+.+?(?=FROM|WHERE|VALUES|SET|TABLE)/gi },
          { type: "Stack Trace", regex: /(Exception|Error):\s*.*?at\s+[\w.<>$_]+\s+\(.*?:\d+:\d+\)/s },
          { type: "IP Address", regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g },
        ];
        
        // Check for sensitive data in response
        const findings = [];
        for (const pattern of sensitivePatterns) {
          const matches = responseBody.match(pattern.regex);
          if (matches && matches.length > 0) {
            findings.push({
              type: pattern.type,
              occurrence: matches.length,
              examples: matches.slice(0, 3), // Show max 3 examples
              severity: getSeverity(pattern.type),
            });
          }
        }
        
        // Check response headers
        const sensitiveHeaders = checkSensitiveHeaders(responseHeaders);
        
        // Check for error details
        const errorDetails = checkErrorDetails(response);
        
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
              text: formatFindings(findings, sensitiveHeaders, errorDetails, endpoint, authInfo),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error checking for sensitive data exposure: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );

  // Test for directory traversal
  server.tool(
    "path_traversal_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      parameter_name: z.string().describe("Name of the parameter to test for path traversal"),
      http_method: z.enum(["GET", "POST"]).default("GET").describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, parameter_name, http_method, use_auth }) => {
      // Path traversal payloads
      const traversalPayloads = [
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\system.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "C:\\Windows\\system.ini",
        "file:///etc/passwd",
        "/dev/null",
        "../../../../../../../../../../../../../../../../etc/hosts",
      ];
      
      const results = [];
      
      try {
        for (const payload of traversalPayloads) {
          const response = await makeRequest(endpoint, parameter_name, payload, http_method, use_auth);
          const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          
          // Check for signs of successful directory traversal
          const suspicious = checkForTraversalSuccess(responseBody, payload);
          
          results.push({
            payload,
            status: response.status,
            size: responseBody.length,
            suspicious,
            notes: suspicious ? "Possible directory traversal vulnerability" : "No clear signs of vulnerability",
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
              text: `Path Traversal Test Results for ${endpoint} (parameter: ${parameter_name})${authInfo}\n\n${results.map(r => 
                `Payload: ${r.payload}\nStatus: ${r.status}\nResponse Size: ${r.size}\nSuspicious: ${r.suspicious}\nNotes: ${r.notes}\n\n`
              ).join('')}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing for path traversal: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
}

/**
 * Helper function to make requests with payloads
 */
async function makeRequest(endpoint: string, paramName: string, paramValue: string, method: string, useAuth: boolean = true) {
  // Prepare the request configuration
  const config: any = {
    method: method.toLowerCase(),
    url: endpoint,
    validateStatus: () => true, // Accept any status code
  };

  // Add authentication headers if available and requested
  if (useAuth) {
    const authManager = AuthManager.getInstance();
    const authState = authManager.getAuthState();
    
    if (authState.type !== 'none' && authState.headers) {
      config.headers = { ...config.headers, ...authState.headers };
    }
  }

  // Add the parameter based on the HTTP method
  if (method === "GET") {
    // For GET requests, add as query parameter
    const url = new URL(endpoint);
    url.searchParams.set(paramName, paramValue);
    config.url = url.toString();
  } else {
    // For POST requests, add in the body
    config.data = { [paramName]: paramValue };
    config.headers = {
      ...config.headers,
      "Content-Type": "application/json",
    };
  }

  return await axios(config);
}

/**
 * Helper function to determine the severity of the finding
 */
function getSeverity(type: string): string {
  const highSeverity = ["Password", "API Key", "JWT", "Social Security Number", "Stack Trace"];
  const mediumSeverity = ["Email Address", "Phone Number", "Internal Path", "SQL Query"];
  const lowSeverity = ["IP Address"];
  
  if (highSeverity.includes(type)) return "High";
  if (mediumSeverity.includes(type)) return "Medium";
  if (lowSeverity.includes(type)) return "Low";
  return "Info";
}

/**
 * Check for sensitive information in headers
 */
function checkSensitiveHeaders(headers: any): Array<{ name: string; value: string; issue: string }> {
  const sensitiveHeaders = [];
  
  // Check for missing security headers
  const securityHeaders = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
  ];
  
  // Look for problematic headers
  if (headers["Server"]) {
    sensitiveHeaders.push({
      name: "Server",
      value: headers["Server"],
      issue: "Reveals server software information",
    });
  }
  
  if (headers["X-Powered-By"]) {
    sensitiveHeaders.push({
      name: "X-Powered-By",
      value: headers["X-Powered-By"],
      issue: "Reveals technology stack information",
    });
  }
  
  // Check for missing security headers
  for (const header of securityHeaders) {
    if (!headers[header]) {
      sensitiveHeaders.push({
        name: header,
        value: "Missing",
        issue: `Missing security header: ${header}`,
      });
    }
  }
  
  return sensitiveHeaders;
}

/**
 * Check for detailed error information in the response
 */
function checkErrorDetails(response: any): any {
  const errorInfo = {
    hasDetailed: false,
    details: "",
  };
  
  // Check status code first
  if (response.status >= 400 && response.status < 600) {
    const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    
    // Look for stack traces
    if (responseBody.includes("at ") && responseBody.includes("line ") && responseBody.includes("file")) {
      errorInfo.hasDetailed = true;
      errorInfo.details = "Stack trace or file paths exposed in error response";
    }
    
    // Look for SQL errors
    if (responseBody.includes("SQL") && responseBody.includes("error")) {
      errorInfo.hasDetailed = true;
      errorInfo.details = "SQL error details exposed";
    }
    
    // Look for exception details
    if (responseBody.includes("Exception") || responseBody.includes("Error:")) {
      errorInfo.hasDetailed = true;
      errorInfo.details = "Exception details exposed";
    }
  }
  
  return errorInfo;
}

/**
 * Format the findings into a readable report
 */
function formatFindings(
  findings: Array<{ type: string; occurrence: number; examples: string[]; severity: string }>,
  sensitiveHeaders: Array<{ name: string; value: string; issue: string }>,
  errorDetails: { hasDetailed: boolean; details: string },
  endpoint: string,
  authInfo: string = ''
): string {
  let report = `# Data Leakage Analysis for ${endpoint}${authInfo}\n\n`;
  
  if (findings.length === 0 && sensitiveHeaders.length === 0 && !errorDetails.hasDetailed) {
    report += "No data leakage detected.\n";
    return report;
  }
  
  if (findings.length > 0) {
    report += "## Sensitive Data in Response\n\n";
    
    for (const finding of findings) {
      report += `- **${finding.type}** (Severity: ${finding.severity})\n`;
      report += `  - Occurrences: ${finding.occurrence}\n`;
      report += `  - Examples: ${finding.examples.map(e => `"${e}"`).join(", ")}\n\n`;
    }
  }
  
  if (sensitiveHeaders.length > 0) {
    report += "## Header Issues\n\n";
    
    for (const header of sensitiveHeaders) {
      report += `- **${header.name}**: ${header.value}\n`;
      report += `  - Issue: ${header.issue}\n\n`;
    }
  }
  
  if (errorDetails.hasDetailed) {
    report += "## Error Handling Issues\n\n";
    report += `- ${errorDetails.details}\n`;
    report += "- Recommendation: Implement proper error handling to avoid leaking implementation details.\n\n";
  }
  
  report += "## Recommendations\n\n";
  report += "1. Implement proper data filtering before sending responses\n";
  report += "2. Add security headers to protect against common attacks\n";
  report += "3. Use generic error messages that don't reveal implementation details\n";
  report += "4. Implement proper content security policies\n";
  report += "5. Avoid including sensitive data in responses unless absolutely necessary\n";
  
  return report;
}

/**
 * Check for signs of successful directory traversal
 */
function checkForTraversalSuccess(responseBody: string, payload: string): boolean {
  // Signs that might indicate successful path traversal
  const unixSigns = [
    "root:x:",
    "bin:x:",
    "/home/",
    "/usr/",
    "Permission denied",
    "No such file or directory",
  ];
  
  const windowsSigns = [
    "[boot loader]",
    "[fonts]",
    "for 16-bit app support",
    "MSDOS.SYS",
    "files=",
    "Access is denied",
  ];
  
  // Check based on payload type
  if (payload.includes("etc/passwd") || payload.includes("/dev/")) {
    return unixSigns.some(sign => responseBody.includes(sign));
  } else if (payload.includes("Windows") || payload.includes("system.ini")) {
    return windowsSigns.some(sign => responseBody.includes(sign));
  }
  
  // Generic suspicious content that might indicate successful traversal
  return (
    (responseBody.includes("/") && responseBody.includes(":") && responseBody.includes("root")) ||
    (responseBody.includes("\\") && responseBody.includes(":") && responseBody.includes("Windows"))
  );
} 