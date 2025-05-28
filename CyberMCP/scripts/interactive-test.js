#!/usr/bin/env node

/**
 * Interactive CyberMCP Testing Script
 * Allows manual testing of specific security tools
 */

import { spawn } from 'child_process';
import { createInterface } from 'readline';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

const serverPath = join(projectRoot, 'dist', 'index.js');

console.log('🔒 CyberMCP Interactive Testing Console\n');

let server;
let rl;
let serverReady = false;

// Available tools for quick reference
const availableTools = {
  'auth': ['basic_auth', 'token_auth', 'oauth2_auth', 'api_login', 'auth_status', 'clear_auth'],
  'jwt': ['jwt_vulnerability_check'],
  'bypass': ['auth_bypass_check'],
  'injection': ['sql_injection_check', 'xss_check'],
  'data': ['sensitive_data_check', 'path_traversal_check'],
  'rate': ['rate_limit_check'],
  'headers': ['security_headers_check']
};

function showHelp() {
  console.log('\n📖 Available Commands:');
  console.log('  help                     - Show this help');
  console.log('  tools                    - List all available tools');
  console.log('  test <tool_name>         - Test a specific tool interactively');
  console.log('  quick-jwt                - Quick JWT vulnerability test');
  console.log('  quick-headers <url>      - Quick security headers test');
  console.log('  quick-auth               - Quick authentication flow test');
  console.log('  resources                - List available resources');
  console.log('  resource <uri>           - Read a specific resource');
  console.log('  exit                     - Exit the interactive console\n');
}

function showTools() {
  console.log('\n🛠️ Available Security Tools:');
  Object.entries(availableTools).forEach(([category, tools]) => {
    console.log(`\n📋 ${category.toUpperCase()}:`);
    tools.forEach(tool => console.log(`  • ${tool}`));
  });
  console.log();
}

function executeToolCall(toolName, params) {
  const request = {
    jsonrpc: '2.0',
    id: Date.now(),
    method: 'tools/call',
    params: {
      name: toolName,
      arguments: params
    }
  };
  
  console.log(`\n📤 Executing: ${toolName}`);
  server.stdin.write(JSON.stringify(request) + '\n');
}

function executeResourceRead(uri) {
  const request = {
    jsonrpc: '2.0',
    id: Date.now(),
    method: 'resources/read',
    params: { uri }
  };
  
  console.log(`\n📚 Reading resource: ${uri}`);
  server.stdin.write(JSON.stringify(request) + '\n');
}

function handleCommand(input) {
  const [command, ...args] = input.trim().split(' ');
  
  switch (command.toLowerCase()) {
    case 'help':
      showHelp();
      break;
      
    case 'tools':
      showTools();
      break;
      
    case 'quick-jwt':
      console.log('\n🧪 Testing JWT with "none" algorithm vulnerability...');
      executeToolCall('jwt_vulnerability_check', {
        jwt_token: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'
      });
      break;
      
    case 'quick-headers':
      const url = args[0] || 'https://httpbin.org/headers';
      console.log(`\n🛡️ Testing security headers for: ${url}`);
      executeToolCall('security_headers_check', { endpoint: url });
      break;
      
    case 'quick-auth':
      console.log('\n🔐 Testing authentication flow...');
      console.log('Step 1: Setting up basic auth...');
      executeToolCall('basic_auth', { username: 'testuser', password: 'testpass' });
      setTimeout(() => {
        console.log('Step 2: Checking auth status...');
        executeToolCall('auth_status', {});
      }, 2000);
      break;
      
    case 'test':
      const toolName = args[0];
      if (!toolName) {
        console.log('❌ Please specify a tool name. Use "tools" to see available tools.');
        break;
      }
      
      // Simple parameter collection for common tools
      if (toolName === 'auth_bypass_check') {
        const endpoint = args[1] || 'https://httpbin.org/basic-auth/user/pass';
        executeToolCall(toolName, { endpoint, use_session_auth: false });
      } else if (toolName === 'sql_injection_check') {
        const endpoint = args[1] || 'https://httpbin.org/get';
        executeToolCall(toolName, { 
          endpoint, 
          parameter_name: 'id', 
          original_value: '1', 
          use_auth: false 
        });
      } else if (toolName === 'security_headers_check') {
        const endpoint = args[1] || 'https://httpbin.org/headers';
        executeToolCall(toolName, { endpoint });
      } else if (toolName === 'auth_status' || toolName === 'clear_auth') {
        executeToolCall(toolName, {});
      } else {
        console.log(`\n🔧 To test ${toolName}, you'll need to provide parameters.`);
        console.log('💡 Try using the quick-* commands for pre-configured tests.');
      }
      break;
      
    case 'resources':
      console.log('\n📚 Available Resources:');
      console.log('  • cybersecurity://checklists/authentication');
      console.log('  • cybersecurity://checklists/injection');
      console.log('  • cybersecurity://checklists/data_leakage');
      console.log('  • guides://api-testing/jwt-testing');
      console.log('  • guides://api-testing/sql-injection');
      console.log('\n💡 Use: resource <uri> to read a specific resource');
      break;
      
    case 'resource':
      const uri = args.join(' ');
      if (!uri) {
        console.log('❌ Please specify a resource URI. Use "resources" to see available resources.');
        break;
      }
      executeResourceRead(uri);
      break;
      
    case 'exit':
      console.log('\n👋 Goodbye! CyberMCP server shutting down...');
      server.kill();
      process.exit(0);
      break;
      
    default:
      console.log(`❌ Unknown command: ${command}`);
      console.log('💡 Type "help" for available commands');
  }
  
  // Show prompt again after a delay
  setTimeout(() => {
    rl.prompt();
  }, 500);
}

function startInteractiveMode() {
  console.log('🚀 Starting CyberMCP server...\n');
  
  // Start the server
  server = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  // Handle server output
  server.stdout.on('data', (data) => {
    const response = data.toString();
    
    try {
      const lines = response.trim().split('\n');
      lines.forEach(line => {
        if (line.trim()) {
          const parsed = JSON.parse(line);
          
          if (parsed.result) {
            if (parsed.result.content) {
              console.log('\n✅ Tool Response:');
              console.log('📄', parsed.result.content[0].text);
            } else if (parsed.result.contents) {
              console.log('\n✅ Resource Content:');
              console.log('📄', parsed.result.contents[0].text.substring(0, 500) + '...');
            } else if (parsed.result.tools) {
              console.log('\n📋 Available Tools:', parsed.result.tools.length);
            }
          } else if (parsed.error) {
            console.log('\n❌ Error:', parsed.error.message);
          }
        }
      });
    } catch (error) {
      // Not JSON, might be regular output
      if (response.trim()) {
        console.log('📤', response.trim());
      }
    }
    
    if (!serverReady) {
      setTimeout(() => rl.prompt(), 100);
    }
  });

  server.stderr.on('data', (data) => {
    const message = data.toString();
    
    if (message.includes('stdio server ready') && !serverReady) {
      serverReady = true;
      console.log('✅ CyberMCP server is ready!\n');
      
      // Initialize the server
      const initRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: {
            name: 'interactive-test-client',
            version: '1.0.0'
          }
        }
      };
      
      server.stdin.write(JSON.stringify(initRequest) + '\n');
      
      setTimeout(() => {
        showHelp();
        console.log('🎯 CyberMCP Interactive Console Ready!');
        console.log('💡 Type a command or "help" for assistance\n');
        rl.prompt();
      }, 1000);
    }
  });

  // Set up readline interface
  rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: '🔒 CyberMCP> '
  });

  rl.on('line', handleCommand);
  
  rl.on('close', () => {
    console.log('\n👋 Goodbye!');
    server.kill();
    process.exit(0);
  });

  // Handle process errors
  server.on('error', (error) => {
    console.error('❌ Server error:', error);
    process.exit(1);
  });
}

startInteractiveMode(); 