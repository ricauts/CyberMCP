# CyberMCP - Cybersecurity API Testing with MCP

CyberMCP is a Model Context Protocol (MCP) server designed for testing backend APIs for security vulnerabilities. It provides a set of specialized tools and resources that can be used by LLMs to identify common security issues in APIs.

## Features

- **Authentication Vulnerability Testing**: Check for JWT vulnerabilities, authentication bypass, and weak authentication mechanisms
- **Injection Testing**: Test for SQL injection, XSS, and other injection vulnerabilities
- **Data Leakage Testing**: Identify sensitive data exposure issues
- **Rate Limiting Testing**: Test for rate limiting bypass and DDoS vulnerabilities
- **Security Headers Testing**: Check for missing or misconfigured security headers
- **Comprehensive Resources**: Access checklists and guides for API security testing
- **Authentication Support**: Multiple authentication methods to test secured endpoints

## Project Structure

```
CyberMCP/
├── src/
│   ├── tools/           # MCP tools for security testing
│   ├── resources/       # MCP resources (checklists, guides)
│   ├── transports/      # Custom transport implementations
│   ├── utils/           # Utility functions and auth management
│   └── index.ts         # Main entry point
├── package.json         # Dependencies and scripts
├── tsconfig.json        # TypeScript configuration
└── README.md            # This file
```

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/CyberMCP.git
   cd CyberMCP
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Build the project:
   ```
   npm run build
   ```

## Usage

### Running the MCP Server

You can run the server using either the stdio transport (default) or HTTP transport:

**Using stdio transport (for integration with LLM platforms):**
```
npm start
```

**Using HTTP transport (for local development and testing):**
```
TRANSPORT=http PORT=3000 npm start
```

### Connecting to the Server

The MCP server can be connected to any MCP client, including LLM platforms that support the Model Context Protocol.

## Security Tools

### Authentication

CyberMCP supports several authentication methods to test secured APIs:

- **Basic Authentication**: Set up HTTP Basic Auth with username and password
- **Token Authentication**: Use bearer tokens, JWT, or custom token formats
- **OAuth2 Authentication**: Full OAuth2 flow support with different grant types
- **Custom API Login**: Authenticate against any login API endpoint

Authentication Tools:
- `basic_auth`: Authenticate with username/password
- `token_auth`: Set up token-based authentication
- `oauth2_auth`: Perform OAuth2 authentication
- `api_login`: Login using a custom API endpoint
- `auth_status`: Check current authentication status
- `clear_auth`: Clear the current authentication state

### Authentication Testing

- **JWT Vulnerability Check**: Analyzes JWT tokens for security issues
- **Authentication Bypass Check**: Tests endpoints for authentication bypass vulnerabilities

### Injection Testing

- **SQL Injection Check**: Tests parameters for SQL injection vulnerabilities
- **XSS Check**: Tests for Cross-Site Scripting vulnerabilities

### Data Leakage Testing

- **Sensitive Data Check**: Identifies leaked PII, credentials, and sensitive information
- **Path Traversal Check**: Tests for directory traversal vulnerabilities

### Security Headers Testing

- **Security Headers Check**: Analyzes HTTP headers for security best practices

## Resources

### Checklists

Access security checklists via `cybersecurity://checklists/{category}` where category can be:
- `authentication`
- `injection`
- `data_leakage`
- `rate_limiting`
- `general`

### Guides

Access detailed testing guides via `guides://api-testing/{topic}` where topic can be:
- `jwt-testing`
- `auth-bypass`
- `sql-injection`
- `xss`
- `rate-limiting`

## Required Information for API Testing

To effectively test an API for security vulnerabilities, you'll need:

1. **API Endpoints**: URLs of the endpoints to test
2. **Authentication Information**: Credentials or tokens for accessing secured endpoints
3. **Parameter Names**: Names of the parameters that accept user input
4. **Test Data**: Sample valid data for parameters
5. **Expected Behavior**: What the normal response should look like
6. **Authentication Flow**: How authentication works in the target API

## Authentication Examples

### Basic Authentication

```
basic_auth:
  username: "admin"
  password: "secure_password"
```

### Token Authentication

```
token_auth:
  token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  token_type: "Bearer"
  expires_in: 3600
```

### OAuth2 Authentication

```
oauth2_auth:
  client_id: "client_123"
  client_secret: "secret_456"
  token_url: "https://example.com/oauth/token"
  grant_type: "client_credentials"
  scope: "read write"
```

### Custom API Login

```
api_login:
  login_url: "https://example.com/api/login"
  credentials: 
    username: "admin"
    password: "secure_password"
  token_path: "data.access_token"
```

## License

MIT