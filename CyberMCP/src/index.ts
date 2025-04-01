import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { HttpSseServerTransport } from "@modelcontextprotocol/sdk/server/http-sse.js";

// Import our security testing tools
import { registerSecurityTools } from "./tools/index.js";
import { registerResources } from "./resources/index.js";

// Create an MCP server
const server = new McpServer({
  name: "CyberMCP",
  version: "0.1.0",
  description: "MCP server for cybersecurity API testing"
});

// Register all our security testing tools
registerSecurityTools(server);

// Register all our resources
registerResources(server);

// Determine which transport to use
const useHttp = process.env.TRANSPORT === "http";

async function main() {
  try {
    if (useHttp) {
      const port = parseInt(process.env.PORT || "3000");
      const transport = new HttpSseServerTransport({ port });
      console.log(`Starting HTTP server on port ${port}...`);
      await server.connect(transport);
    } else {
      // Default to stdio
      console.error("Starting CyberMCP with stdio transport...");
      const transport = new StdioServerTransport();
      await server.connect(transport);
    }
  } catch (error) {
    console.error("Error starting server:", error);
    process.exit(1);
  }
}

main(); 