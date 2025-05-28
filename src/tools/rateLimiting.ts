import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager } from "../utils/authManager.js";

/**
 * Register rate limiting testing tools
 */
export function registerRateLimitingTools(server: McpServer) {
  // Rate limit testing tool
  server.tool(
    "rate_limit_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      requests_per_second: z.number().min(1).max(100).default(10).describe("Number of requests per second to send"),
      duration_seconds: z.number().min(1).max(30).default(5).describe("Duration of the test in seconds"),
      method: z.enum(['GET', 'POST', 'PUT', 'DELETE']).default('GET').describe("HTTP method to use"),
      use_auth: z.boolean().default(true).describe("Whether to use current authentication if available"),
    },
    async ({ endpoint, requests_per_second, duration_seconds, method, use_auth }) => {
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
        
        // Initialize test results
        const results = {
          totalRequests: 0,
          successfulRequests: 0,
          rateLimitedRequests: 0,
          otherErrors: 0,
          rateLimitHeaders: new Set<string>(),
          responseTimeStats: {
            min: Number.MAX_VALUE,
            max: 0,
            total: 0,
          },
          statusCodes: {} as Record<number, number>,
        };
        
        // Calculate delay between requests
        const delayMs = Math.floor(1000 / requests_per_second);
        const endTime = Date.now() + (duration_seconds * 1000);
        
        // Make requests
        while (Date.now() < endTime) {
          const startTime = Date.now();
          
          try {
            const response = await axios({
              method: method.toLowerCase(),
              url: endpoint,
              headers,
              validateStatus: () => true, // Accept any status code
            });
            
            const responseTime = Date.now() - startTime;
            
            // Update response time stats
            results.responseTimeStats.min = Math.min(results.responseTimeStats.min, responseTime);
            results.responseTimeStats.max = Math.max(results.responseTimeStats.max, responseTime);
            results.responseTimeStats.total += responseTime;
            
            // Update status code counts
            results.statusCodes[response.status] = (results.statusCodes[response.status] || 0) + 1;
            
            // Check for rate limit headers
            const rateLimitHeaders = extractRateLimitHeaders(response.headers);
            rateLimitHeaders.forEach(header => results.rateLimitHeaders.add(header));
            
            // Update request counts
            results.totalRequests++;
            if (response.status === 429) {
              results.rateLimitedRequests++;
            } else if (response.status >= 200 && response.status < 300) {
              results.successfulRequests++;
            } else {
              results.otherErrors++;
            }
          } catch (error) {
            results.totalRequests++;
            results.otherErrors++;
          }
          
          // Wait for the next request interval
          const elapsed = Date.now() - startTime;
          if (elapsed < delayMs) {
            await new Promise(resolve => setTimeout(resolve, delayMs - elapsed));
          }
        }
        
        // Generate report
        return {
          content: [
            {
              type: "text",
              text: generateReport(results, endpoint, method, requests_per_second, duration_seconds),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing rate limits: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
}

/**
 * Extract rate limit headers from response
 */
function extractRateLimitHeaders(headers: any): string[] {
  const rateLimitHeaders = [];
  
  // Common rate limit headers
  const headerPatterns = [
    /^x-ratelimit-/i,
    /^ratelimit-/i,
    /^x-rate-limit-/i,
    /^retry-after$/i,
  ];
  
  for (const key in headers) {
    if (headerPatterns.some(pattern => pattern.test(key))) {
      rateLimitHeaders.push(`${key}: ${headers[key]}`);
    }
  }
  
  return rateLimitHeaders;
}

/**
 * Generate test report
 */
function generateReport(
  results: any,
  endpoint: string,
  method: string,
  requestsPerSecond: number,
  durationSeconds: number
): string {
  let report = `Rate Limit Test Report\n\n`;
  
  // Test configuration
  report += `Test Configuration:\n`;
  report += `- Endpoint: ${endpoint}\n`;
  report += `- HTTP Method: ${method}\n`;
  report += `- Target Rate: ${requestsPerSecond} requests/second\n`;
  report += `- Duration: ${durationSeconds} seconds\n\n`;
  
  // Request statistics
  report += `Request Statistics:\n`;
  report += `- Total Requests: ${results.totalRequests}\n`;
  report += `- Successful Requests: ${results.successfulRequests} (${((results.successfulRequests / results.totalRequests) * 100).toFixed(1)}%)\n`;
  report += `- Rate Limited (429): ${results.rateLimitedRequests} (${((results.rateLimitedRequests / results.totalRequests) * 100).toFixed(1)}%)\n`;
  report += `- Other Errors: ${results.otherErrors} (${((results.otherErrors / results.totalRequests) * 100).toFixed(1)}%)\n\n`;
  
  // Response time statistics
  if (results.totalRequests > 0) {
    report += `Response Time Statistics:\n`;
    report += `- Minimum: ${results.responseTimeStats.min}ms\n`;
    report += `- Maximum: ${results.responseTimeStats.max}ms\n`;
    report += `- Average: ${(results.responseTimeStats.total / results.totalRequests).toFixed(1)}ms\n\n`;
  }
  
  // Status code distribution
  report += `Status Code Distribution:\n`;
  Object.entries(results.statusCodes)
    .sort(([a], [b]) => parseInt(a) - parseInt(b))
    .forEach(([code, count]) => {
      report += `- ${code}: ${count} (${((count as number / results.totalRequests) * 100).toFixed(1)}%)\n`;
    });
  report += `\n`;
  
  // Rate limit headers
  if (results.rateLimitHeaders.size > 0) {
    report += `Rate Limit Headers Detected:\n`;
    Array.from(results.rateLimitHeaders).forEach(header => {
      report += `- ${header}\n`;
    });
    report += `\n`;
  }
  
  // Analysis and recommendations
  report += `Analysis:\n`;
  
  if (results.rateLimitedRequests > 0) {
    report += `- Rate limiting is implemented and active\n`;
    const rateLimitThreshold = (results.totalRequests / durationSeconds).toFixed(1);
    report += `- Rate limit threshold appears to be around ${rateLimitThreshold} requests/second\n`;
  } else if (results.totalRequests > 0) {
    report += `- No rate limiting detected at ${requestsPerSecond} requests/second\n`;
    report += `- Consider implementing rate limiting for API protection\n`;
  }
  
  if (results.rateLimitHeaders.size === 0) {
    report += `- No standard rate limit headers detected\n`;
    report += `- Consider implementing standard rate limit headers for better client integration\n`;
  }
  
  report += `\nRecommendations:\n`;
  report += `1. Implement consistent rate limiting across all endpoints\n`;
  report += `2. Use standard rate limit headers (X-RateLimit-*)\n`;
  report += `3. Include Retry-After headers with 429 responses\n`;
  report += `4. Consider implementing different limits for:\n`;
  report += `   - Authenticated vs unauthenticated requests\n`;
  report += `   - Different API endpoints based on resource intensity\n`;
  report += `   - Different client types or subscription levels\n`;
  report += `5. Monitor and adjust rate limits based on:\n`;
  report += `   - Server resource utilization\n`;
  report += `   - API usage patterns\n`;
  report += `   - Client needs and feedback\n`;
  
  return report;
}