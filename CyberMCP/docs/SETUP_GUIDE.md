# CyberMCP - Complete Setup and Configuration Guide

## 🔒 CyberMCP - AI-Powered API Security Testing

CyberMCP is a Model Context Protocol (MCP) server designed to help AI agents test backend APIs for security vulnerabilities. It provides a comprehensive suite of tools for authentication testing, injection testing, data leakage detection, rate limiting validation, and security headers analysis.

## 📋 Prerequisites

Before setting up CyberMCP, ensure you have:

- **Node.js** (version 18 or higher)
- **npm** or **yarn** package manager
- One of the supported AI IDEs:
  - **Claude Desktop**
  - **Cursor IDE**
  - **Windsurf (Codeium)**
  - **VS Code with Cline extension**

## 🚀 Installation and Build

### 1. Clone and Install Dependencies

```bash
# Clone the repository
git clone https://github.com/your-username/CyberMCP.git
cd CyberMCP

# Install dependencies
npm install

# Build the project
npm run build
```

### 2. Verify Installation

Test the server with the MCP Inspector:

```bash
# Run the MCP Inspector to test your server
npm run inspector
```

This will open a web interface where you can test the MCP server functionality.

## 🔧 IDE Configuration

### Claude Desktop Configuration

1. **Locate Claude Desktop Config File:**
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

2. **Add CyberMCP Configuration:**

```json
{
  "mcpServers": {
    "cybermcp": {
      "command": "node",
      "args": ["C:/path/to/CyberMCP/dist/index.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

3. **Restart Claude Desktop**

### Cursor IDE Configuration

1. **Open Cursor Settings** (`Ctrl/Cmd + ,`)

2. **Add to User Settings:**

```json
{
  "mcp": {
    "servers": {
      "cybermcp": {
        "command": "node",
        "args": ["dist/index.js"],
        "cwd": "/path/to/CyberMCP",
        "env": {
          "NODE_ENV": "production"
        }
      }
    }
  }
}
```

3. **Restart Cursor IDE**

### Windsurf (Codeium) Configuration

1. **Open Windsurf Settings**

2. **Add MCP Server Configuration:**

```json
{
  "mcpServers": {
    "cybermcp": {
      "command": "node",
      "args": ["/path/to/CyberMCP/dist/index.js"],
      "cwd": "/path/to/CyberMCP",
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

3. **Restart Windsurf**

### VS Code with Cline Extension

1. **Install the Cline Extension** from the VS Code marketplace

2. **Configure Cline Settings:**

```json
{
  "cline.mcpServers": {
    "cybermcp": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/CyberMCP"
    }
  }
}
```

3. **Restart VS Code**

## 🏃‍♂️ Running Modes

### Stdio Mode (Default - for IDE integration)

```bash
npm start
```

### HTTP Mode (for remote access)

```bash
TRANSPORT=http PORT=3000 npm start
```

The HTTP server will be available at `http://localhost:3000`

## 🛠️ Available Security Tools

### 🔐 Authentication Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `basic_auth` | Set up HTTP Basic Authentication | Set username and password |
| `token_auth` | Configure Bearer/JWT token authentication | Set token and type |
| `oauth2_auth` | Perform OAuth2 authentication flow | Configure client credentials |
| `api_login` | Login via custom API endpoint | Login with custom credentials |
| `auth_status` | Check current authentication status | View auth configuration |
| `clear_auth` | Clear authentication state | Reset authentication |
| `jwt_vulnerability_check` | Analyze JWT tokens for security issues | Check JWT algorithm, expiration |
| `auth_bypass_check` | Test for authentication bypass vulnerabilities | Test endpoint access control |

### 💉 Injection Testing Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `sql_injection_check` | Test for SQL injection vulnerabilities | Test parameter with SQL payloads |
| `xss_check` | Test for Cross-Site Scripting vulnerabilities | Test parameter with XSS payloads |

### 📊 Data Leakage Testing Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `sensitive_data_check` | Detect sensitive data exposure | Check for PII, credentials leakage |
| `path_traversal_check` | Test for directory traversal vulnerabilities | Test file path parameters |

### ⏱️ Rate Limiting Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `rate_limiting_check` | Test rate limiting effectiveness | Send multiple rapid requests |

### 🛡️ Security Headers Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `security_headers_check` | Analyze HTTP security headers | Check HSTS, CSP, X-Frame-Options |

## 📚 Usage Examples

### Example 1: Basic API Security Assessment

```text
I need to test the security of my API at https://api.example.com/users

1. First, authenticate:
   - Use basic_auth with username "admin" and password "password123"

2. Check authentication bypass:
   - Use auth_bypass_check on https://api.example.com/users endpoint

3. Test for SQL injection:
   - Use sql_injection_check on the "id" parameter

4. Check security headers:
   - Use security_headers_check on the base URL
```

### Example 2: JWT Token Analysis

```text
I have a JWT token that I want to analyze for security issues:

Use jwt_vulnerability_check with the token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Example 3: OAuth2 Authentication Testing

```text
Test an API that uses OAuth2:

1. Authenticate with OAuth2:
   - Use oauth2_auth with client_id, client_secret, and token_url
   
2. Test the protected endpoints:
   - Use auth_bypass_check to ensure proper access control
```

## 🔍 Resources Available

The server also provides access to security testing resources:

- **Checklists**: Access via `cybersecurity://checklists/{category}`
  - Categories: `authentication`, `injection`, `data_leakage`, `rate_limiting`, `general`
  
- **Guides**: Access via `guides://api-testing/{topic}`
  - Topics: `jwt-testing`, `auth-bypass`, `sql-injection`, `xss`, `rate-limiting`

## 🐛 Troubleshooting

### Common Issues

1. **"Command not found" error:**
   - Ensure Node.js is installed and in your PATH
   - Verify the path to the built `dist/index.js` file is correct

2. **"Module not found" errors:**
   - Run `npm install` to ensure all dependencies are installed
   - Run `npm run build` to ensure the project is built

3. **Authentication not working:**
   - Use `auth_status` tool to check current authentication state
   - Ensure you're using the correct authentication method for your API

4. **IDE not recognizing the server:**
   - Restart the IDE after adding the configuration
   - Check that the file paths in the configuration are absolute and correct

### Debug Mode

For debugging issues, run the server with additional logging:

```bash
NODE_ENV=development npm start
```

## 📖 Additional Resources

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

## 🤝 Contributing

To contribute to CyberMCP:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**🔒 Happy Security Testing!** 

For issues and support, please create an issue in the repository. 