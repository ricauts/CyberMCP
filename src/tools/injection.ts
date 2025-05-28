import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register injection security testing tools
 */
export function registerInjectionTools(server: McpServer) {
  // SQL Injection tester
  server.tool(
    "sql_injection_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      parameter_name: z.string().describe("Name of the parameter to test for SQL injection"),
      http_method: z.enum(["GET", "POST", "PUT"]).default("GET").describe("HTTP method to use"),
      original_value: z.string().describe("Original value for the parameter"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, parameter_name, http_method, original_value, use_auth }) => {
      // SQL injection payloads to test
      const sqlPayloads = [
        "' OR '1'='1",
        "1' OR '1'='1",
        "admin'--",
        "1' OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "1'; DROP TABLE users--",
        "1' UNION SELECT null,null,null,null,concat(username,':',password) FROM users--",
      ];

      const results = [];

      try {
        // First, make a regular request as baseline
        const baselineResponse = await makeRequest(endpoint, parameter_name, original_value, http_method, use_auth);
        const baselineStatus = baselineResponse.status;
        const baselineLength = baselineResponse.data ? JSON.stringify(baselineResponse.data).length : 0;

        results.push({
          test: "Baseline (Original Value)",
          payload: original_value,
          status: baselineStatus,
          response_size: baselineLength,
          notes: "Baseline for comparison",
        });

        // Test each SQL injection payload
        for (const payload of sqlPayloads) {
          const response = await makeRequest(endpoint, parameter_name, payload, http_method, use_auth);
          const status = response.status;
          const responseLength = response.data ? JSON.stringify(response.data).length : 0;
          const sizeDifference = responseLength - baselineLength;
          
          let vulnerability = "None detected";
          
          // Check for potential vulnerabilities based on response differences
          if (status !== baselineStatus) {
            vulnerability = "Potential: Different status code from baseline";
          } else if (Math.abs(sizeDifference) > baselineLength * 0.5) {
            vulnerability = "Potential: Significant response size difference";
          } else if (response.data && typeof response.data === 'object' && 
                    baselineResponse.data && typeof baselineResponse.data === 'object' &&
                    Object.keys(response.data).length !== Object.keys(baselineResponse.data).length) {
            vulnerability = "Potential: Different response structure";
          } else if (response.data && typeof response.data === 'string' && 
                    response.data.includes("SQL") && response.data.includes("error")) {
            vulnerability = "High: SQL error message exposed";
          }

          results.push({
            test: "SQL Injection Test",
            payload: payload,
            status: status,
            response_size: responseLength,
            size_difference: sizeDifference,
            vulnerability: vulnerability,
          });
        }

        // Add authentication information to the report
        const authManager = AuthManager.getInstance();
        const authState = authManager.getAuthState();
        const authInfo = use_auth && authState.type !== 'none' 
          ? `\nTests performed with authentication: ${authState.type}` 
          : '\nTests performed without authentication';

        return {
          content: [
            {
              type: "text",
              text: `SQL Injection Test Results for ${endpoint} (parameter: ${parameter_name})${authInfo}\n\n${
                results.map(r => 
                  `Test: ${r.test}\nPayload: ${r.payload}\nStatus: ${r.status}\nResponse Size: ${r.response_size} bytes\n${
                    r.size_difference !== undefined ? `Size Difference: ${r.size_difference} bytes\n` : ''
                  }${
                    r.vulnerability ? `Vulnerability: ${r.vulnerability}\n` : ''
                  }${
                    r.notes ? `Notes: ${r.notes}\n` : ''
                  }\n`
                ).join('\n')
              }`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing SQL injection: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );

  // XSS (Cross-Site Scripting) tester
  server.tool(
    "xss_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      parameter_name: z.string().describe("Name of the parameter to test for XSS"),
      http_method: z.enum(["GET", "POST", "PUT"]).default("GET").describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, parameter_name, http_method, use_auth }) => {
      // XSS payloads to test
      const xssPayloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "'-alert('XSS')-'",
      ];

      const results = [];

      try {
        for (const payload of xssPayloads) {
          const response = await makeRequest(endpoint, parameter_name, payload, http_method, use_auth);
          const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          
          // Check if the payload is reflected in the response
          const isReflected = responseBody.includes(payload);
          
          // Check if it seems to be encoded
          const isEncoded = !isReflected && (
            responseBody.includes(payload.replace(/</g, '&lt;')) || 
            responseBody.includes(payload.replace(/>/g, '&gt;')) ||
            responseBody.includes(encodeURIComponent(payload))
          );
          
          results.push({
            payload: payload,
            status: response.status,
            reflected: isReflected,
            encoded: isEncoded,
            vulnerability: isReflected ? "Potential XSS vulnerability - payload reflected without encoding" : 
                           isEncoded ? "Low - payload reflected but encoded" : "None detected",
          });
        }

        // Add authentication information to the report
        const authManager = AuthManager.getInstance();
        const authState = authManager.getAuthState();
        const authInfo = use_auth && authState.type !== 'none' 
          ? `\nTests performed with authentication: ${authState.type}` 
          : '\nTests performed without authentication';

        return {
          content: [
            {
              type: "text",
              text: `XSS Test Results for ${endpoint} (parameter: ${parameter_name})${authInfo}\n\n${
                results.map(r => 
                  `Payload: ${r.payload}\nStatus: ${r.status}\nReflected: ${r.reflected}\nEncoded: ${r.encoded}\nVulnerability: ${r.vulnerability}\n\n`
                ).join('')
              }`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing XSS vulnerability: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
}

/**
 * Helper function to make requests with various payloads
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
    // For POST/PUT requests, add in the body
    config.data = { [paramName]: paramValue };
    config.headers = {
      ...config.headers,
      "Content-Type": "application/json",
    };
  }

  return await axios(config);
} 