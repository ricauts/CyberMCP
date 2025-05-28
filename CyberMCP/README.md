# 🔒 CyberMCP

**AI-powered Cybersecurity API Testing with Model Context Protocol (MCP)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4%2B-blue.svg)](https://www.typescriptlang.org/)

CyberMCP is a Model Context Protocol (MCP) server that enables AI agents to perform comprehensive security testing on backend APIs. It provides 14 specialized security tools and 10 resources for identifying vulnerabilities like authentication bypass, injection attacks, data leakage, and security misconfigurations.

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/your-username/CyberMCP.git
cd CyberMCP
npm install
npm run build

# Test the server
npm run test-server

# Start interactive testing
npm run test-interactive
```

## ✨ Features

- **🔐 Authentication Testing** - JWT analysis, bypass detection, OAuth2 flows
- **💉 Injection Testing** - SQL injection, XSS vulnerability detection  
- **📊 Data Protection** - Sensitive data exposure, path traversal checks
- **⏱️ Rate Limiting** - DoS vulnerability assessment
- **🛡️ Security Headers** - OWASP security header validation
- **📚 Comprehensive Resources** - Security checklists and testing guides

## 🛠️ Security Tools (14 Total)

| Category | Tools |
|----------|-------|
| **Authentication** | `basic_auth`, `token_auth`, `oauth2_auth`, `api_login`, `auth_status`, `clear_auth`, `jwt_vulnerability_check`, `auth_bypass_check` |
| **Injection Testing** | `sql_injection_check`, `xss_check` |
| **Data Protection** | `sensitive_data_check`, `path_traversal_check` |
| **Infrastructure** | `rate_limit_check`, `security_headers_check` |

## 🎯 IDE Integration

CyberMCP works with all major AI-powered IDEs:

- **Claude Desktop** - Direct MCP integration
- **Cursor IDE** - Built-in MCP support  
- **Windsurf (Codeium)** - Native MCP protocol
- **VS Code + Cline** - Extension-based integration

> 📖 **[Complete Setup Guide](docs/SETUP_GUIDE.md)** - Detailed configuration for each IDE

## 📋 Usage Example

```text
"Use basic_auth with username 'admin' and password 'secret123' 
then use auth_bypass_check on https://api.example.com/users 
to test for authentication bypass vulnerabilities"
```

The AI agent will:
1. Configure authentication credentials
2. Test the protected endpoint for bypass vulnerabilities  
3. Provide detailed security analysis and recommendations

## 📊 Testing & Validation

```bash
# Comprehensive tool testing
npm run test-tools

# Manual interactive testing  
npm run test-interactive

# Quick setup verification
npm run quick-start

# MCP Inspector (GUI)
npm run inspector
```

## 📁 Project Structure

```
CyberMCP/
├── src/                    # TypeScript source code
│   ├── tools/             # 14 security testing tools
│   ├── resources/         # Security checklists & guides
│   └── utils/             # Authentication & utilities
├── docs/                  # Documentation
├── scripts/               # Testing & utility scripts  
├── examples/              # Configuration examples
├── dist/                  # Built JavaScript (generated)
└── README.md              # This file
```

## 🔧 Development

```bash
# Development mode with hot reload
npm run dev

# Build TypeScript
npm run build

# Start server (stdio mode)
npm start

# Start HTTP server
TRANSPORT=http PORT=3000 npm start
```

## 📖 Documentation

- **[Setup Guide](docs/SETUP_GUIDE.md)** - Detailed installation and configuration
- **[Project Summary](docs/PROJECT_SUMMARY.md)** - Complete feature overview
- **[Testing Results](docs/TESTING_RESULTS.md)** - Validation and test coverage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-security-tool`
3. Make your changes and add tests
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [Model Context Protocol](https://modelcontextprotocol.io/) - Official MCP documentation
- [OWASP API Security](https://owasp.org/www-project-api-security/) - API security best practices
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) - Development framework

---

**🔒 Secure your APIs with AI-powered testing!**

*For support and questions, please [create an issue](https://github.com/your-username/CyberMCP/issues).* 