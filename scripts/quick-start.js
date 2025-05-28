#!/usr/bin/env node

/**
 * CyberMCP Quick Start Script
 * Automatically sets up and tests the CyberMCP server
 */

import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

const execAsync = promisify(exec);

console.log('🔒 CyberMCP Quick Start Setup\n');

async function runCommand(command, description) {
  console.log(`📋 ${description}...`);
  try {
    const { stdout, stderr } = await execAsync(command, { cwd: projectRoot });
    if (stderr && !stderr.includes('npm WARN')) {
      console.log('⚠️  Warning:', stderr);
    }
    console.log('✅ Completed\n');
    return true;
  } catch (error) {
    console.error(`❌ Failed: ${error.message}\n`);
    return false;
  }
}

async function quickStart() {
  console.log('🚀 Starting CyberMCP Quick Setup...\n');

  // Step 1: Check if we're in the right directory
  if (!existsSync(join(projectRoot, 'package.json'))) {
    console.error('❌ Please run this script from the CyberMCP project root directory.');
    process.exit(1);
  }

  // Step 2: Install dependencies
  const installSuccess = await runCommand('npm install', 'Installing dependencies');
  if (!installSuccess) {
    console.error('❌ Failed to install dependencies. Please check your Node.js installation.');
    process.exit(1);
  }

  // Step 3: Build project
  const buildSuccess = await runCommand('npm run build', 'Building TypeScript project');
  if (!buildSuccess) {
    console.error('❌ Failed to build project. Please check for TypeScript errors.');
    process.exit(1);
  }

  // Step 4: Test server
  console.log('🧪 Testing CyberMCP server...');
  const testSuccess = await runCommand('npm run test-server', 'Running server tests');
  if (!testSuccess) {
    console.error('❌ Server tests failed. Please check the build.');
    process.exit(1);
  }

  // Step 5: Show configuration options
  console.log('🎯 CyberMCP is ready! Choose your IDE configuration:\n');
  
  console.log('📋 Configuration Files Created:');
  console.log('  • examples/mcp-config/claude-desktop.json - Claude Desktop configuration');
  console.log('  • examples/mcp-config/cursor-settings.json - Cursor IDE configuration');  
  console.log('  • examples/mcp-config/windsurf-config.json - Windsurf configuration\n');

  console.log('🔧 Next Steps:');
  console.log('  1. Choose your IDE from the list above');
  console.log('  2. Copy the appropriate config to your IDE settings');
  console.log('  3. Update the file paths in the config to match your system');
  console.log('  4. Restart your IDE\n');

  console.log('📖 Documentation:');
  console.log('  • README.md - Quick start guide');
  console.log('  • docs/SETUP_GUIDE.md - Detailed setup instructions\n');

  console.log('🧪 Testing Commands:');
  console.log('  • npm run test-server - Test MCP protocol communication');
  console.log('  • npm run inspector - Open interactive MCP inspector');
  console.log('  • npm start - Start server in stdio mode');
  console.log('  • TRANSPORT=http PORT=3000 npm start - Start HTTP server\n');

  console.log('🛠️ Available Security Tools (14 tools):');
  console.log('  🔐 Authentication: basic_auth, token_auth, oauth2_auth, api_login, auth_status, clear_auth, jwt_vulnerability_check, auth_bypass_check');
  console.log('  💉 Injection Testing: sql_injection_check, xss_check');
  console.log('  📊 Data Protection: sensitive_data_check, path_traversal_check');
  console.log('  ⏱️ Rate Limiting: rate_limit_check');
  console.log('  🛡️ Security Headers: security_headers_check\n');

  console.log('📚 Available Resources (10 resources):');
  console.log('  📋 Checklists: cybersecurity://checklists/{authentication,injection,data_leakage,rate_limiting,general}');
  console.log('  📖 Guides: guides://api-testing/{jwt-testing,auth-bypass,sql-injection,xss,rate-limiting}\n');

  console.log('✨ Example Usage in your IDE:');
  console.log('   "Use basic_auth to authenticate with username \'admin\' and password \'secret\'"');
  console.log('   "Use sql_injection_check on https://api.example.com/users with parameter \'id\' and original value \'1\'"');
  console.log('   "Use security_headers_check on https://api.example.com"\n');

  console.log('🎉 CyberMCP setup completed successfully!');
  console.log('🔒 Ready to secure your APIs with AI-powered testing!');
}

quickStart().catch(error => {
  console.error('💥 Quick start failed:', error);
  process.exit(1);
}); 