import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";

/**
 * Register rate limiting security testing tools
 */
export function registerRateLimitingTools(server: McpServer) {
  // Rate limiting test
  server.tool(
    "rate_limit_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      http_method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("GET").describe("HTTP method to use"),
      request_count: z.number().min(5).max(50).default(20).describe("Number of requests to send"),
      request_delay_ms: z.number().min(0).max(1000).default(100).describe("Delay between requests in milliseconds"),
      auth_header: z.string().optional().describe("Authentication header (if any)"),
      request_body: z.string().optional().describe("Request body (for POST/PUT requests)"),
    },
    async ({ endpoint, http_method, request_count, request_delay_ms, auth_header, request_body }) => {
      try {
        const results = [];
        let rateLimitDetected = false;
        let rateLimitThreshold = 0;
        let lastStatusCode = 0;
        
        // Make a sequence of requests to detect rate limiting
        for (let i = 0; i < request_count; i++) {
          // Make the request
          const response = await axios({
            method: http_method.toLowerCase(),
            url: endpoint,
            data: request_body ? JSON.parse(request_body) : undefined,
            headers: auth_header ? { Authorization: auth_header } : undefined,
            validateStatus: () => true, // Accept any status code
          });
          
          // Check for rate limiting response
          const isRateLimited = isRateLimitingResponse(response);
          const rateLimitHeaders = extractRateLimitHeaders(response.headers);
          
          results.push({
            request_number: i + 1,
            status: response.status,
            rate_limited: isRateLimited,
            headers: rateLimitHeaders,
          });
          
          // If we detect rate limiting, note when it happened
          if (isRateLimited && !rateLimitDetected) {
            rateLimitDetected = true;
            rateLimitThreshold = i + 1;
          }
          
          lastStatusCode = response.status;
          
          // If we've already been rate limited, we can stop testing
          if (rateLimitDetected && i >= rateLimitThreshold + 2) {
            break;
          }
          
          // Add delay between requests
          if (i < request_count - 1 && request_delay_ms > 0) {
            await new Promise(resolve => setTimeout(resolve, request_delay_ms));
          }
        }
        
        // Analyze results
        const analysis = analyzeRateLimiting(results, rateLimitDetected, rateLimitThreshold);
        
        return {
          content: [
            {
              type: "text",
              text: formatRateLimitResults(results, analysis, endpoint),
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
}

/**
 * Check if a response indicates rate limiting
 */
function isRateLimitingResponse(response: any): boolean {
  // Check status code (429 is the standard for rate limiting)
  if (response.status === 429) {
    return true;
  }
  
  // Check for common rate limit headers
  const headers = response.headers || {};
  const headerKeys = Object.keys(headers).map(h => h.toLowerCase());
  
  if (
    headerKeys.some(h => h.includes("ratelimit") || h.includes("rate-limit") || h.includes("x-rate"))
  ) {
    return true;
  }
  
  // Check response body for rate limit messages
  const responseBody = typeof response.data === 'string' 
    ? response.data.toLowerCase()
    : JSON.stringify(response.data || "").toLowerCase();
    
  return (
    responseBody.includes("rate limit") ||
    responseBody.includes("ratelimit") ||
    responseBody.includes("too many requests") ||
    responseBody.includes("exceeded") ||
    responseBody.includes("throttle") ||
    responseBody.includes("slow down")
  );
}

/**
 * Extract rate limiting headers from response
 */
function extractRateLimitHeaders(headers: any): Record<string, string> {
  const result: Record<string, string> = {};
  const headerKeys = Object.keys(headers || {});
  
  // Look for common rate limit headers
  const rateLimitHeaderPatterns = [
    /^x-ratelimit/i,
    /^ratelimit/i,
    /^x-rate-limit/i,
    /^rate-limit/i,
    /^retry-after/i,
    /^x-retry-after/i,
  ];
  
  for (const key of headerKeys) {
    if (rateLimitHeaderPatterns.some(pattern => pattern.test(key))) {
      result[key] = headers[key];
    }
  }
  
  return result;
}

/**
 * Analyze rate limiting behavior
 */
function analyzeRateLimiting(
  results: Array<{ request_number: number; status: number; rate_limited: boolean; headers: Record<string, string> }>,
  rateLimitDetected: boolean,
  rateLimitThreshold: number
): any {
  // If no rate limiting detected
  if (!rateLimitDetected) {
    return {
      has_rate_limiting: false,
      vulnerability: "High - No rate limiting detected",
      recommendation: "Implement rate limiting to protect against abuse and DDoS attacks",
    };
  }
  
  // If rate limiting was detected
  const firstRateLimitedRequest = results.find(r => r.rate_limited);
  const headers = firstRateLimitedRequest?.headers || {};
  const hasRetryAfter = Object.keys(headers).some(h => 
    h.toLowerCase().includes("retry") || h.toLowerCase().includes("reset")
  );
  
  return {
    has_rate_limiting: true,
    threshold: rateLimitThreshold,
    provides_retry_info: hasRetryAfter,
    vulnerability: rateLimitThreshold < 5 
      ? "Low - Rate limiting detected with low threshold"
      : rateLimitThreshold < 20
        ? "Medium - Rate limiting detected with moderate threshold" 
        : "High - Rate limiting detected with high threshold",
    recommendation: hasRetryAfter
      ? "Current implementation seems reasonable, consider adjusting threshold if needed"
      : "Add Retry-After header to help clients know when to resume requests",
  };
}

/**
 * Format rate limiting results into a readable report
 */
function formatRateLimitResults(
  results: Array<{ request_number: number; status: number; rate_limited: boolean; headers: Record<string, string> }>,
  analysis: any,
  endpoint: string
): string {
  let report = `# Rate Limiting Analysis for ${endpoint}\n\n`;
  
  report += `## Summary\n\n`;
  report += `- Rate Limiting Detected: ${analysis.has_rate_limiting ? "Yes" : "No"}\n`;
  
  if (analysis.has_rate_limiting) {
    report += `- Rate Limit Threshold: ~ ${analysis.threshold} requests\n`;
    report += `- Provides Retry Information: ${analysis.provides_retry_info ? "Yes" : "No"}\n`;
  }
  
  report += `- Vulnerability Assessment: ${analysis.vulnerability}\n`;
  report += `- Recommendation: ${analysis.recommendation}\n\n`;
  
  report += `## Request Results\n\n`;
  
  // Display only the important results to save space
  const significantResults = results.filter(r => 
    r.rate_limited || 
    r.request_number === 1 || 
    r.request_number === results.length ||
    (analysis.has_rate_limiting && Math.abs(r.request_number - analysis.threshold) <= 1)
  );
  
  for (const result of significantResults) {
    report += `### Request ${result.request_number}\n`;
    report += `- Status Code: ${result.status}\n`;
    report += `- Rate Limited: ${result.rate_limited ? "Yes" : "No"}\n`;
    
    if (Object.keys(result.headers).length > 0) {
      report += "- Rate Limit Headers:\n";
      for (const [key, value] of Object.entries(result.headers)) {
        report += `  - ${key}: ${value}\n`;
      }
    }
    
    report += "\n";
  }
  
  report += `## Best Practices for Rate Limiting\n\n`;
  report += `1. Use standard status code 429 Too Many Requests\n`;
  report += `2. Include Retry-After headers\n`;
  report += `3. Document rate limits in API documentation\n`;
  report += `4. Consider different limits for different endpoints based on sensitivity\n`;
  report += `5. Implement escalating cooldowns for repeat offenders\n`;
  
  return report;
} 