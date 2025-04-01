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
}