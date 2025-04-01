import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";
import { AuthManager, BasicAuthCredentials, TokenAuthCredentials, OAuth2Config } from "../utils/authManager.js";

/**
 * Register authentication security testing tools
 */
export function registerAuthenticationTools(server: McpServer) {
  // Basic authentication tool
  server.tool(
    "basic_auth",
    {
      username: z.string().describe("Username for authentication"),
      password: z.string().describe("Password for authentication"),
    },
    async ({ username, password }) => {
      try {
        const authManager = AuthManager.getInstance();
        const authState = await authManager.setBasicAuth({ username, password });
        
        return {
          content: [
            {
              type: "text",
              text: `Successfully set Basic authentication with username: ${username}\nAuthentication type: ${authState.type}\nHeader: Authorization: Basic ***`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error setting Basic authentication: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
  
  // Token authentication tool
  server.tool(
    "token_auth",
    {
      token: z.string().describe("Authentication token"),
      token_type: z.string().default("Bearer").describe("Token type (Bearer, JWT, etc.)"),
      refresh_token: z.string().optional().describe("Refresh token (if available)"),
      expires_in: z.number().optional().describe("Token expiration time in seconds"),
    },
    async ({ token, token_type, refresh_token, expires_in }) => {
      try {
        const authManager = AuthManager.getInstance();
        const authState = await authManager.setTokenAuth({
          token,
          tokenType: token_type,
          refreshToken: refresh_token,
          expiresIn: expires_in,
        });
        
        return {
          content: [
            {
              type: "text",
              text: `Successfully set Token authentication\nAuthentication type: ${authState.type}\nToken type: ${token_type}\nHeader: Authorization: ${token_type} ***\n${authState.tokenExpiry ? `Token expires: ${authState.tokenExpiry.toISOString()}` : ''}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error setting Token authentication: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
  
  // OAuth2 authentication tool
  server.tool(
    "oauth2_auth",
    {
      client_id: z.string().describe("OAuth2 client ID"),
      client_secret: z.string().optional().describe("OAuth2 client secret"),
      token_url: z.string().url().describe("OAuth2 token endpoint URL"),
      authorization_url: z.string().url().optional().describe("OAuth2 authorization endpoint URL (for authorization code flow)"),
      grant_type: z.enum(['client_credentials', 'password', 'authorization_code', 'refresh_token']).default('client_credentials').describe("OAuth2 grant type"),
      username: z.string().optional().describe("Username (for password grant type)"),
      password: z.string().optional().describe("Password (for password grant type)"),
      scope: z.string().optional().describe("OAuth2 scope"),
      redirect_uri: z.string().optional().describe("Redirect URI (for authorization code flow)"),
    },
    async ({ client_id, client_secret, token_url, authorization_url, grant_type, username, password, scope, redirect_uri }) => {
      try {
        const authManager = AuthManager.getInstance();
        
        // Validate required parameters for specific grant types
        if (grant_type === 'password' && (!username || !password)) {
          throw new Error("Username and password are required for password grant type");
        }
        
        if (grant_type === 'authorization_code' && !redirect_uri) {
          throw new Error("Redirect URI is required for authorization code grant type");
        }
        
        // Configure OAuth2
        const config: OAuth2Config = {
          clientId: client_id,
          clientSecret: client_secret,
          tokenUrl: token_url,
          authorizationUrl: authorization_url || "",
          grantType: grant_type as any,
          username,
          password,
          scope,
          redirectUri: redirect_uri
        };
        
        const authState = await authManager.authenticateWithOAuth2(config);
        
        return {
          content: [
            {
              type: "text",
              text: `Successfully authenticated with OAuth2\nGrant type: ${grant_type}\nToken type: ${authState.token ? 'Bearer' : 'Unknown'}\n${authState.tokenExpiry ? `Token expires: ${authState.tokenExpiry.toISOString()}` : ''}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error authenticating with OAuth2: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
  
  // Custom API login tool
  server.tool(
    "api_login",
    {
      login_url: z.string().url().describe("API login endpoint URL"),
      credentials: z.record(z.string()).describe("Login credentials as key-value pairs"),
      method: z.enum(['post', 'get']).default('post').describe("HTTP method to use"),
      token_path: z.string().default("token").describe("Path to token in the response (e.g., 'data.accessToken')"),
      token_prefix: z.string().default("Bearer").describe("Token prefix to use in Authorization header"),
      header_name: z.string().default("Authorization").describe("Header name to use for the token"),
    },
    async ({ login_url, credentials, method, token_path, token_prefix, header_name }) => {
      try {
        const authManager = AuthManager.getInstance();
        
        const authState = await authManager.authenticateWithApi(
          login_url,
          credentials,
          {
            method,
            tokenPath: token_path,
            tokenPrefix: token_prefix,
            headerName: header_name
          }
        );
        
        return {
          content: [
            {
              type: "text",
              text: `Successfully authenticated with API login\nEndpoint: ${login_url}\nToken header: ${header_name}: ${token_prefix} ***\n${authState.tokenExpiry ? `Token expires: ${authState.tokenExpiry.toISOString()}` : ''}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error logging in to API: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
  
  // Get current auth status
  server.tool(
    "auth_status",
    {},
    async () => {
      const authManager = AuthManager.getInstance();
      const authState = authManager.getAuthState();
      
      let statusText = "";
      
      if (authState.type === 'none') {
        statusText = "No authentication configured. Use basic_auth, token_auth, oauth2_auth, or api_login to authenticate.";
      } else {
        statusText = `Current authentication type: ${authState.type}\n`;
        
        if (authState.type === 'basic') {
          statusText += `Username: ${authState.username}\n`;
          statusText += `Authentication header: Authorization: Basic ***\n`;
        } else if (authState.type === 'token' || authState.type === 'oauth2') {
          statusText += `Token: ${authState.token?.substring(0, 10)}***\n`;
          if (authState.refreshToken) {
            statusText += `Refresh token: Available\n`;
          }
          if (authState.tokenExpiry) {
            const now = new Date();
            const isExpired = now > authState.tokenExpiry;
            statusText += `Token expires: ${authState.tokenExpiry.toISOString()} (${isExpired ? 'EXPIRED' : 'Valid'})\n`;
          }
          if (authState.headers) {
            statusText += `Authentication headers: ${Object.keys(authState.headers).join(', ')}\n`;
          }
        }
      }
      
      return {
        content: [
          {
            type: "text",
            text: statusText,
          },
        ],
      };
    }
  );
  
  // Clear authentication
  server.tool(
    "clear_auth",
    {},
    async () => {
      const authManager = AuthManager.getInstance();
      authManager.clearAuth();
      
      return {
        content: [
          {
            type: "text",
            text: "Authentication cleared. The server is no longer authenticated.",
          },
        ],
      };
    }
  );

  // Test for JWT weakness
  server.tool(
    "jwt_vulnerability_check",
    {
      jwt_token: z.string().describe("JWT token to analyze for vulnerabilities"),
    },
    async ({ jwt_token }) => {
      try {
        // Split the token
        const parts = jwt_token.split(".");
        if (parts.length !== 3) {
          return {
            content: [
              {
                type: "text",
                text: "Invalid JWT format. Expected 3 parts (header.payload.signature).",
              },
            ],
          };
        }

        // Decode header
        const headerBase64 = parts[0];
        const headerJson = Buffer.from(headerBase64, "base64").toString();
        const header = JSON.parse(headerJson);

        // Decode payload
        const payloadBase64 = parts[1];
        const payloadJson = Buffer.from(payloadBase64, "base64").toString();
        const payload = JSON.parse(payloadJson);

        // Check for security issues
        const issues = [];

        // Check algorithm
        if (header.alg === "none") {
          issues.push("Critical: 'none' algorithm used - authentication can be bypassed");
        }

        if (header.alg === "HS256" || header.alg === "RS256") {
          // These are generally good, but we'll note it
        } else {
          issues.push(`Warning: Unusual algorithm ${header.alg} - verify if intended`);
        }

        // Check expiration
        if (!payload.exp) {
          issues.push("High: No expiration claim (exp) - token never expires");
        } else {
          const expDate = new Date(payload.exp * 1000);
          const now = new Date();
          if (expDate < now) {
            issues.push(`Info: Token expired on ${expDate.toISOString()}`);
          } else {
            const daysDiff = Math.floor((expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
            if (daysDiff > 30) {
              issues.push(`Medium: Long expiration time (${daysDiff} days) - consider shorter lifetime`);
            }
          }
        }

        // Check for missing recommended claims
        if (!payload.iat) {
          issues.push("Low: Missing 'issued at' claim (iat)");
        }
        if (!payload.iss) {
          issues.push("Low: Missing 'issuer' claim (iss)");
        }
        if (!payload.sub) {
          issues.push("Low: Missing 'subject' claim (sub)");
        }

        return {
          content: [
            {
              type: "text",
              text: issues.length > 0
                ? `JWT Analysis Results:\n\nHeader: ${JSON.stringify(header, null, 2)}\n\nPayload: ${JSON.stringify(payload, null, 2)}\n\nSecurity Issues:\n${issues.join("\n")}`
                : `JWT Analysis Results:\n\nHeader: ${JSON.stringify(header, null, 2)}\n\nPayload: ${JSON.stringify(payload, null, 2)}\n\nNo security issues detected.`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error analyzing JWT: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );

  // Test for authentication bypass
  server.tool(
    "auth_bypass_check",
    {
      endpoint: z.string().url().describe("API endpoint to test"),
      auth_header: z.string().optional().describe("Authentication header name (if different from standard)"),
      auth_token: z.string().optional().describe("Authentication token (if not using the currently authenticated session)"),
      http_method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).default("GET").describe("HTTP method to use"),
      use_session_auth: z.boolean().default(true).describe("Whether to use the current session authentication if available"),
    },
    async ({ endpoint, auth_header, auth_token, http_method, use_session_auth }) => {
      const results = [];
      const authManager = AuthManager.getInstance();
      const currentAuthState = authManager.getAuthState();
      const hasCurrentAuth = currentAuthState.type !== 'none' && use_session_auth;

      try {
        // Test 1: No authentication
        const noAuthResponse = await axios({
          method: http_method.toLowerCase(),
          url: endpoint,
          validateStatus: () => true, // Accept any status code
        });

        results.push({
          test: "No Authentication",
          status: noAuthResponse.status,
          vulnerable: noAuthResponse.status < 400, // Vulnerable if not returning 4xx error
          details: `Response without authentication returned status code ${noAuthResponse.status}`,
        });

        // Test 2: Invalid token
        const headerName = auth_header || "Authorization";
        const invalidTokenResponse = await axios({
          method: http_method.toLowerCase(),
          url: endpoint,
          headers: {
            [headerName]: "Bearer invalid_token_here",
          },
          validateStatus: () => true,
        });

        results.push({
          test: "Invalid Token",
          status: invalidTokenResponse.status,
          vulnerable: invalidTokenResponse.status < 400,
          details: `Response with invalid token returned status code ${invalidTokenResponse.status}`,
        });

        // Test 3: Empty token
        const emptyTokenResponse = await axios({
          method: http_method.toLowerCase(),
          url: endpoint,
          headers: {
            [headerName]: "",
          },
          validateStatus: () => true,
        });

        results.push({
          test: "Empty Token",
          status: emptyTokenResponse.status,
          vulnerable: emptyTokenResponse.status < 400,
          details: `Response with empty token returned status code ${emptyTokenResponse.status}`,
        });

        // Test 4: If we have current auth or a provided token, test with valid auth
        if (hasCurrentAuth || auth_token) {
          let authHeaders = {};
          
          if (hasCurrentAuth) {
            authHeaders = authManager.getAuthHeaders();
          } else if (auth_token) {
            authHeaders = {
              [headerName]: `Bearer ${auth_token}`,
            };
          }
          
          const validAuthResponse = await axios({
            method: http_method.toLowerCase(),
            url: endpoint,
            headers: authHeaders,
            validateStatus: () => true,
          });
          
          results.push({
            test: "Valid Authentication",
            status: validAuthResponse.status,
            authorized: validAuthResponse.status < 400,
            details: `Response with valid authentication returned status code ${validAuthResponse.status}`,
          });
          
          // Check if we get the same response with and without auth
          const authBypassRisk = noAuthResponse.status === validAuthResponse.status && 
                               noAuthResponse.status < 400 && 
                               JSON.stringify(noAuthResponse.data) === JSON.stringify(validAuthResponse.data);
          
          if (authBypassRisk) {
            results.push({
              test: "Authentication Effectiveness",
              vulnerable: true,
              details: "CRITICAL: Endpoint returns the same response with and without authentication. Authentication may be ineffective.",
            });
          }
        }

        return {
          content: [
            {
              type: "text",
              text: `Authentication Bypass Test Results for ${endpoint}:\n\n${results.map(r => 
                `Test: ${r.test}\n${r.status ? `Status: ${r.status}\n` : ''}${r.vulnerable !== undefined ? `Vulnerable: ${r.vulnerable}\n` : ''}${r.authorized !== undefined ? `Authorized: ${r.authorized}\n` : ''}Details: ${r.details}\n`
              ).join("\n")}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error testing authentication bypass: ${(error as Error).message}`,
            },
          ],
        };
      }
    }
  );
} 