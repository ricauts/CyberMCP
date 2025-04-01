import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register rate limiting security testing tools
 */
export function registerRateLimitingTools(server: McpServer) {
  // Rate limiting test tool
  server.tool(
    "rate_limit_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      http_method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("GET").describe("HTTP method to use"),
      request_body: z.string().optional().describe("Request body (for POST/PUT requests)"),
      requests_per_second: z.number().min(1).max(100).default(10).describe("Number of requests per second to attempt"),
      test_duration_seconds: z.number().min(1).max(30).default(5).describe("Duration of the test in seconds"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, http_method, request_body, requests_per_second, test_duration_seconds, use_auth }) => {
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
        
        // Initialize test variables
        const results = [];
        const startTime = Date.now();
        const endTime = startTime + (test_duration_seconds * 1000);
        let totalRequests = 0;
        let successfulRequests = 0;
        let rateLimitedRequests = 0;
        let otherErrors = 0;
        
        // Track rate limit headers
        const rateLimitHeaders = new Set([
          'x-ratelimit-limit',
          'x-ratelimit-remaining',
          'x-ratelimit-reset',
          'retry-after',
          'ratelimit-limit',
          'ratelimit-remaining',
          'ratelimit-reset',
        ]);
        
        // Make requests
        while (Date.now() < endTime) {
          const batchStartTime = Date.now();
          const promises = [];
          
          // Create batch of requests
          for (let i = 0; i < requests_per_second; i++) {
            promises.push(
              axios({
                method: http_method.toLowerCase(),
                url: endpoint,
                data: request_body ? JSON.parse(request_body) : undefined,
                headers,
                validateStatus: () => true, // Accept any status code
              })
            );
          }
          
          // Wait for batch to complete
          const responses = await Promise.all(promises);
          
          // Process responses
          for (const response of responses) {
            totalRequests++;
            
            // Check for rate limit headers
            const limitHeaders = {};
            for (const [header, value] of Object.entries(response.headers)) {
              if (rateLimitHeaders.has(header.toLowerCase())) {
                limitHeaders[header] = value;
              }
            }
            
            // Categorize response
            if (response.status === 200) {
              successfulRequests++;
            } else if (
              response.status === 429 ||
              response.status === 503 ||
              Object.keys(limitHeaders).length > 0
            ) {
              rateLimitedRequests++;
            } else {
              otherErrors++;
            }
            
            // Store result
            results.push({
              timestamp: Date.now(),
              status: response.status,
              headers: limitHeaders,
              responseTime: response.config?.transitional?.timeout || 0,
            });
          }
          
          // Calculate delay for next batch
          const batchEndTime = Date.now();
          const batchDuration = batchEndTime - batchStartTime;
          const targetBatchDuration = 1000; // 1 second
          
          if (batchDuration < targetBatchDuration) {
            await new Promise(resolve => setTimeout(resolve, targetBatchDuration - batchDuration));
          }
        }
        
        // Calculate metrics
        const actualDuration = (Date.now() - startTime) / 1000;
        const actualRequestsPerSecond = totalRequests / actualDuration;
        const successRate = (successfulRequests / totalRequests) * 100;
        const rateLimitRate = (rateLimitedRequests / totalRequests) * 100;
        
        // Analyze rate limiting behavior
        const analysis = analyzeRateLimiting(results);
        
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
              text: formatRateLimitResults(
                endpoint,
                {
                  totalRequests,
                  successfulRequests,
                  rateLimitedRequests,
                  otherErrors,
                  actualRequestsPerSecond,
                  successRate,
                  rateLimitRate,
                  duration: actualDuration,
                },
                analysis,
                authInfo
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing rate limiting: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );

  // Concurrent sessions test tool
  server.tool(
    "concurrent_sessions_check",
    {
      login_endpoint: z.string().url().describe("Login API endpoint"),
      test_endpoint: z.string().url().describe("API endpoint to test with authenticated sessions"),
      login_credentials: z.string().describe("Login credentials in JSON format"),
      concurrent_sessions: z.number().min(1).max(10).default(5).describe("Number of concurrent sessions to attempt"),
    },
    async ({ login_endpoint, test_endpoint, login_credentials, concurrent_sessions }) => {
      try {
        const credentials = JSON.parse(login_credentials);
        const sessions = [];
        const results = [];
        
        // Create multiple sessions
        for (let i = 0; i < concurrent_sessions; i++) {
          try {
            // Login and get session token
            const loginResponse = await axios.post(login_endpoint, credentials);
            
            if (loginResponse.status === 200 && loginResponse.data) {
              // Store session information
              sessions.push({
                id: i + 1,
                token: extractToken(loginResponse),
                loginTime: Date.now(),
              });
            }
          } catch (error) {
            results.push({
              sessionId: i + 1,
              status: "Login Failed",
              error: (error as Error).message,
            });
          }
        }
        
        // Test all sessions
        for (const session of sessions) {
          try {
            // Make request with session token
            const response = await axios.get(test_endpoint, {
              headers: {
                Authorization: `Bearer ${session.token}`,
              },
              validateStatus: () => true,
            });
            
            results.push({
              sessionId: session.id,
              status: response.status === 200 ? "Active" : "Invalid",
              statusCode: response.status,
              responseTime: response.config?.transitional?.timeout || 0,
            });
          } catch (error) {
            results.push({
              sessionId: session.id,
              status: "Request Failed",
              error: (error as Error).message,
            });
          }
        }
        
        return {
          content: [
            {
              type: "text",
              text: formatConcurrentSessionResults(results, concurrent_sessions),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing concurrent sessions: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
}

/**
 * Analyze rate limiting behavior from results
 */
function analyzeRateLimiting(results: Array<{
  timestamp: number;
  status: number;
  headers: Record<string, string>;
  responseTime: number;
}>): {
  hasRateLimit: boolean;
  limitValue?: number;
  resetPeriod?: number;
  pattern?: string;
  consistency: string;
} {
  const analysis = {
    hasRateLimit: false,
    limitValue: undefined,
    resetPeriod: undefined,
    pattern: undefined,
    consistency: "No rate limiting detected",
  };
  
  // Check if any rate limit headers were found
  const hasLimitHeaders = results.some(r => Object.keys(r.headers).length > 0);
  
  if (hasLimitHeaders) {
    analysis.hasRateLimit = true;
    
    // Try to determine limit value
    const limitHeaders = results
      .map(r => r.headers)
      .filter(h => h['x-ratelimit-limit'] || h['ratelimit-limit']);
    
    if (limitHeaders.length > 0) {
      analysis.limitValue = parseInt(limitHeaders[0]['x-ratelimit-limit'] || limitHeaders[0]['ratelimit-limit']);
    }
    
    // Try to determine reset period
    const resetHeaders = results
      .map(r => r.headers)
      .filter(h => h['x-ratelimit-reset'] || h['ratelimit-reset']);
    
    if (resetHeaders.length > 0) {
      const resetTime = parseInt(resetHeaders[0]['x-ratelimit-reset'] || resetHeaders[0]['ratelimit-reset']);
      analysis.resetPeriod = resetTime - Math.floor(Date.now() / 1000);
    }
    
    // Analyze consistency
    const rateLimitResponses = results.filter(r => r.status === 429).length;
    const totalResponses = results.length;
    
    if (rateLimitResponses > 0) {
      const ratio = rateLimitResponses / totalResponses;
      if (ratio > 0.8) {
        analysis.pattern = "Strict rate limiting";
        analysis.consistency = "Very consistent rate limiting";
      } else if (ratio > 0.5) {
        analysis.pattern = "Moderate rate limiting";
        analysis.consistency = "Somewhat consistent rate limiting";
      } else {
        analysis.pattern = "Loose rate limiting";
        analysis.consistency = "Inconsistent rate limiting";
      }
    } else if (hasLimitHeaders) {
      analysis.pattern = "Header-based rate limiting";
      analysis.consistency = "Rate limit headers present but no blocking";
    }
  }
  
  return analysis;
}

/**
 * Format rate limit test results into a readable report
 */
function formatRateLimitResults(
  endpoint: string,
  metrics: {
    totalRequests: number;
    successfulRequests: number;
    rateLimitedRequests: number;
    otherErrors: number;
    actualRequestsPerSecond: number;
    successRate: number;
    rateLimitRate: number;
    duration: number;
  },
  analysis: {
    hasRateLimit: boolean;
    limitValue?: number;
    resetPeriod?: number;
    pattern?: string;
    consistency: string;
  },
  authInfo: string = ''
): string {
  let report = `# Rate Limiting Test Results for ${endpoint}${authInfo}\n\n`;
  
  // Add test metrics
  report += `## Test Metrics\n\n`;
  report += `- Total Requests: ${metrics.totalRequests}\n`;
  report += `- Duration: ${metrics.duration.toFixed(2)} seconds\n`;
  report += `- Actual Requests/Second: ${metrics.actualRequestsPerSecond.toFixed(2)}\n`;
  report += `- Successful Requests: ${metrics.successfulRequests} (${metrics.successRate.toFixed(2)}%)\n`;
  report += `- Rate Limited Requests: ${metrics.rateLimitedRequests} (${metrics.rateLimitRate.toFixed(2)}%)\n`;
  report += `- Other Errors: ${metrics.otherErrors}\n\n`;
  
  // Add analysis
  report += `## Rate Limiting Analysis\n\n`;
  report += `- Rate Limiting Detected: ${analysis.hasRateLimit ? "Yes" : "No"}\n`;
  if (analysis.limitValue) {
    report += `- Rate Limit Value: ${analysis.limitValue} requests\n`;
  }
  if (analysis.resetPeriod) {
    report += `- Reset Period: ${analysis.resetPeriod} seconds\n`;
  }
  if (analysis.pattern) {
    report += `- Pattern: ${analysis.pattern}\n`;
  }
  report += `- Consistency: ${analysis.consistency}\n\n`;
  
  // Add recommendations
  report += `## Recommendations\n\n`;
  
  if (!analysis.hasRateLimit) {
    report += `- Implement rate limiting to protect against abuse\n`;
    report += `- Consider using token bucket or leaky bucket algorithms\n`;
    report += `- Add rate limit headers for transparency\n`;
  } else if (metrics.successRate > 90) {
    report += `- Consider stricter rate limiting policies\n`;
    report += `- Implement progressive rate limiting\n`;
    report += `- Monitor for abuse patterns\n`;
  } else if (metrics.rateLimitRate > 90) {
    report += `- Current rate limits may be too restrictive\n`;
    report += `- Consider adjusting limits based on user roles\n`;
    report += `- Implement retry-after headers\n`;
  } else {
    report += `- Monitor rate limiting effectiveness\n`;
    report += `- Consider implementing rate limiting analytics\n`;
    report += `- Review rate limiting policies periodically\n`;
  }
  
  return report;
}

/**
 * Format concurrent session test results into a readable report
 */
function formatConcurrentSessionResults(
  results: Array<{
    sessionId: number;
    status: string;
    statusCode?: number;
    responseTime?: number;
    error?: string;
  }>,
  attemptedSessions: number
): string {
  let report = `# Concurrent Sessions Test Results\n\n`;
  
  // Calculate metrics
  const activeSessions = results.filter(r => r.status === "Active").length;
  const failedLogins = results.filter(r => r.status === "Login Failed").length;
  const invalidSessions = results.filter(r => r.status === "Invalid").length;
  const failedRequests = results.filter(r => r.status === "Request Failed").length;
  
  // Add summary
  report += `## Summary\n\n`;
  report += `- Attempted Sessions: ${attemptedSessions}\n`;
  report += `- Active Sessions: ${activeSessions}\n`;
  report += `- Failed Logins: ${failedLogins}\n`;
  report += `- Invalid Sessions: ${invalidSessions}\n`;
  report += `- Failed Requests: ${failedRequests}\n\n`;
  
  // Add detailed results
  report += `## Detailed Results\n\n`;
  
  for (const result of results) {
    report += `### Session ${result.sessionId}\n`;
    report += `- Status: ${result.status}\n`;
    if (result.statusCode) {
      report += `- Status Code: ${result.statusCode}\n`;
    }
    if (result.responseTime) {
      report += `- Response Time: ${result.responseTime}ms\n`;
    }
    if (result.error) {
      report += `- Error: ${result.error}\n`;
    }
    report += "\n";
  }
  
  // Add analysis and recommendations
  report += `## Analysis and Recommendations\n\n`;
  
  if (activeSessions === attemptedSessions) {
    report += `- The application allows multiple concurrent sessions\n`;
    report += `- Consider implementing session limits if needed\n`;
    report += `- Monitor for suspicious concurrent session patterns\n`;
  } else if (activeSessions === 1) {
    report += `- The application enforces single session policy\n`;
    report += `- Ensure proper session invalidation on new logins\n`;
    report += `- Consider adding session notifications\n`;
  } else if (activeSessions === 0) {
    report += `- No sessions were successfully established\n`;
    report += `- Review authentication mechanism\n`;
    report += `- Check for rate limiting or security controls\n`;
  } else {
    report += `- Inconsistent session behavior detected\n`;
    report += `- Review session management implementation\n`;
    report += `- Consider implementing clear session policies\n`;
  }
  
  return report;
}

/**
 * Extract authentication token from login response
 */
function extractToken(response: any): string {
  // Check common token locations in response
  if (response.data.token) {
    return response.data.token;
  }
  if (response.data.access_token) {
    return response.data.access_token;
  }
  if (response.data.jwt) {
    return response.data.jwt;
  }
  
  // Check authorization header
  const authHeader = response.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // If no token found, throw error
  throw new Error('No authentication token found in response');
}