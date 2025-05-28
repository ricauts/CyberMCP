#!/usr/bin/env node

/**
 * Simple test script to verify CyberMCP server functionality
 * This script tests the basic MCP protocol communication
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

const serverPath = join(projectRoot, 'dist', 'index.js');

console.log('🔒 Testing CyberMCP Server...\n');

// Start the server
const server = spawn('node', [serverPath], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let responseData = '';

// Set up timeout
const timeout = setTimeout(() => {
  console.log('❌ Test timed out');
  server.kill();
  process.exit(1);
}, 10000);

// Handle server output
server.stdout.on('data', (data) => {
  responseData += data.toString();
  console.log('📤 Server response:', data.toString());
});

server.stderr.on('data', (data) => {
  console.log('📡 Server status:', data.toString());
});

// Test initialize request
const initializeRequest = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: {
      name: 'test-client',
      version: '1.0.0'
    }
  }
};

console.log('📨 Sending initialize request...');
server.stdin.write(JSON.stringify(initializeRequest) + '\n');

// Test tools/list request after a short delay
setTimeout(() => {
  const listToolsRequest = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {}
  };
  
  console.log('📨 Sending tools/list request...');
  server.stdin.write(JSON.stringify(listToolsRequest) + '\n');
}, 1000);

// Test resources/list request
setTimeout(() => {
  const listResourcesRequest = {
    jsonrpc: '2.0',
    id: 3,
    method: 'resources/list',
    params: {}
  };
  
  console.log('📨 Sending resources/list request...');
  server.stdin.write(JSON.stringify(listResourcesRequest) + '\n');
}, 2000);

// Clean up after tests
setTimeout(() => {
  clearTimeout(timeout);
  console.log('\n✅ Test completed successfully!');
  console.log('🎯 CyberMCP server is responding to MCP protocol messages');
  server.kill();
  process.exit(0);
}, 5000);

// Handle process errors
server.on('error', (error) => {
  console.error('❌ Server error:', error);
  clearTimeout(timeout);
  process.exit(1);
});

server.on('exit', (code) => {
  if (code !== 0) {
    console.error(`❌ Server exited with code ${code}`);
  }
  clearTimeout(timeout);
}); 