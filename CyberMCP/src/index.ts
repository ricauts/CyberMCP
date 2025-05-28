#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import process from "process";

// Import our security testing tools
import { registerSecurityTools } from "./tools/index.js";
import { registerResources } from "./resources/index.js";

// Create an MCP server
const server = new McpServer({
  name: "CyberMCP",
  version: "0.2.0",
  description: "MCP server for cybersecurity API testing and vulnerability assessment"
});

// Register all our security testing tools
registerSecurityTools(server);

// Register all our resources
registerResources(server);

// Determine which transport to use
const transportType = process.env.TRANSPORT || "stdio";

async function main() {
  try {
    console.error("=================================================");
    console.error("🔒 CyberMCP - Cybersecurity API Testing Server");
    console.error(`Version: 0.2.0 | Transport: ${transportType}`);
    console.error("=================================================");

    if (transportType === "http") {
      const port = parseInt(process.env.PORT || "3000", 10);
      console.error(`🌐 Starting HTTP server on port ${port}...`);
      
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => `cybermcp-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
        onsessioninitialized: (sessionId: string) => {
          console.error(`📁 Session initialized: ${sessionId}`);
        }
      });

      await server.connect(transport);
      console.error(`✅ CyberMCP HTTP server ready on http://localhost:${port}`);
    } else {
      // Default to stdio transport
      console.error("📡 Starting CyberMCP with stdio transport...");
      const transport = new StdioServerTransport();
      await server.connect(transport);
      console.error("✅ CyberMCP stdio server ready");
    }
  } catch (error) {
    console.error("❌ Error starting CyberMCP server:", error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.error("\n🔄 Shutting down CyberMCP server...");
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.error("\n🔄 Shutting down CyberMCP server...");
  process.exit(0);
});

main().catch((error) => {
  console.error("💥 Fatal error:", error);
  process.exit(1);
}); 