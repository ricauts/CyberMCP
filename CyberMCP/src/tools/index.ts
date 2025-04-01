import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerAuthenticationTools } from "./authentication.js";
import { registerInjectionTools } from "./injection.js";
import { registerDataLeakageTools } from "./dataLeakage.js";
import { registerRateLimitingTools } from "./rateLimiting.js";
import { registerSecurityHeadersTools } from "./securityHeaders.js";

/**
 * Register all security testing tools with the MCP server
 */
export function registerSecurityTools(server: McpServer) {
  registerAuthenticationTools(server);
  registerInjectionTools(server);
  registerDataLeakageTools(server);
  registerRateLimitingTools(server);
  registerSecurityHeadersTools(server);
} 