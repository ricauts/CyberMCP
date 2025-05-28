import axios from 'axios';

/**
 * Authentication state interface
 */
export interface AuthState {
  type: 'token' | 'oauth2' | 'basic' | 'none';
  token?: string;
  refreshToken?: string;
  tokenExpiry?: Date;
  username?: string;
  password?: string; // Note: In a production app, we'd use more secure storage
  oauthTokens?: any;
  headers?: Record<string, string>;
}

/**
 * Basic auth credentials
 */
export interface BasicAuthCredentials {
  username: string;
  password: string;
}

/**
 * Token auth credentials
 */
export interface TokenAuthCredentials {
  token: string;
  tokenType?: string;
  refreshToken?: string;
  expiresIn?: number;
}

/**
 * OAuth2 configuration
 */
export interface OAuth2Config {
  clientId: string;
  clientSecret?: string;
  authorizationUrl: string;
  tokenUrl: string;
  redirectUri?: string;
  scope?: string;
  grantType?: 'authorization_code' | 'client_credentials' | 'password' | 'refresh_token';
  username?: string;
  password?: string;
}

/**
 * Authentication Manager to handle different auth methods
 */
export class AuthManager {
  private static instance: AuthManager;
  private authState: AuthState = { type: 'none' };
  
  private constructor() {
    // Private constructor for singleton pattern
  }
  
  /**
   * Get singleton instance
   */
  public static getInstance(): AuthManager {
    if (!AuthManager.instance) {
      AuthManager.instance = new AuthManager();
    }
    return AuthManager.instance;
  }
  
  /**
   * Get current auth state
   */
  public getAuthState(): AuthState {
    return { ...this.authState };
  }
  
  /**
   * Clear auth state
   */
  public clearAuth(): void {
    this.authState = { type: 'none' };
  }
  
  /**
   * Set token auth
   */
  public async setTokenAuth(credentials: TokenAuthCredentials): Promise<AuthState> {
    const { token, tokenType = 'Bearer', refreshToken, expiresIn } = credentials;
    
    // Calculate token expiry if expiresIn is provided
    let tokenExpiry: Date | undefined;
    if (expiresIn) {
      tokenExpiry = new Date();
      tokenExpiry.setSeconds(tokenExpiry.getSeconds() + expiresIn);
    }
    
    this.authState = {
      type: 'token',
      token,
      refreshToken,
      tokenExpiry,
      headers: {
        'Authorization': `${tokenType} ${token}`
      }
    };
    
    return this.getAuthState();
  }
  
  /**
   * Set basic auth
   */
  public async setBasicAuth(credentials: BasicAuthCredentials): Promise<AuthState> {
    const { username, password } = credentials;
    
    // Create Base64 encoded credentials
    const base64Credentials = Buffer.from(`${username}:${password}`).toString('base64');
    
    this.authState = {
      type: 'basic',
      username,
      password,
      headers: {
        'Authorization': `Basic ${base64Credentials}`
      }
    };
    
    return this.getAuthState();
  }
  
  /**
   * Authenticate with OAuth2
   */
  public async authenticateWithOAuth2(config: OAuth2Config): Promise<AuthState> {
    const { 
      clientId, 
      clientSecret, 
      tokenUrl, 
      grantType = 'client_credentials',
      username,
      password,
      scope,
      redirectUri
    } = config;
    
    try {
      let data: Record<string, string> = {
        client_id: clientId,
        grant_type: grantType
      };
      
      // Add optional parameters based on grant type
      if (clientSecret) {
        data.client_secret = clientSecret;
      }
      
      if (scope) {
        data.scope = scope;
      }
      
      if (redirectUri) {
        data.redirect_uri = redirectUri;
      }
      
      // Add credentials for password grant
      if (grantType === 'password' && username && password) {
        data.username = username;
        data.password = password;
      }
      
      // Execute the token request
      const response = await axios.post(tokenUrl, new URLSearchParams(data), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      
      const { 
        access_token, 
        refresh_token, 
        expires_in, 
        token_type = 'Bearer'
      } = response.data;
      
      // Calculate token expiry
      let tokenExpiry: Date | undefined;
      if (expires_in) {
        tokenExpiry = new Date();
        tokenExpiry.setSeconds(tokenExpiry.getSeconds() + expires_in);
      }
      
      // Update auth state
      this.authState = {
        type: 'oauth2',
        token: access_token,
        refreshToken: refresh_token,
        tokenExpiry,
        oauthTokens: response.data,
        headers: {
          'Authorization': `${token_type} ${access_token}`
        }
      };
      
      return this.getAuthState();
    } catch (error) {
      throw new Error(`OAuth2 authentication failed: ${(error as Error).message}`);
    }
  }
  
  /**
   * Authenticate with a custom API login endpoint
   */
  public async authenticateWithApi(
    loginUrl: string, 
    credentials: Record<string, string>, 
    options: {
      method?: 'post' | 'get',
      tokenPath?: string,
      tokenPrefix?: string,
      refreshTokenPath?: string,
      expiresInPath?: string,
      headerName?: string
    } = {}
  ): Promise<AuthState> {
    const { 
      method = 'post',
      tokenPath = 'token',
      tokenPrefix = 'Bearer',
      refreshTokenPath = 'refreshToken',
      expiresInPath = 'expiresIn',
      headerName = 'Authorization'
    } = options;
    
    try {
      // Make the request to the login endpoint
      const response = method === 'post' 
        ? await axios.post(loginUrl, credentials)
        : await axios.get(loginUrl, { params: credentials });
      
      // Extract token from response using the path
      const getNestedValue = (obj: any, path: string): any => {
        return path.split('.').reduce((prev, curr) => {
          return prev && prev[curr];
        }, obj);
      };
      
      const token = getNestedValue(response.data, tokenPath);
      if (!token) {
        throw new Error(`Token not found in response at path: ${tokenPath}`);
      }
      
      // Extract other optional values
      const refreshToken = getNestedValue(response.data, refreshTokenPath);
      const expiresIn = getNestedValue(response.data, expiresInPath);
      
      // Calculate token expiry
      let tokenExpiry: Date | undefined;
      if (expiresIn) {
        tokenExpiry = new Date();
        tokenExpiry.setSeconds(tokenExpiry.getSeconds() + Number(expiresIn));
      }
      
      // Update auth state
      this.authState = {
        type: 'token',
        token,
        refreshToken,
        tokenExpiry,
        headers: {
          [headerName]: `${tokenPrefix} ${token}`
        }
      };
      
      return this.getAuthState();
    } catch (error) {
      throw new Error(`API authentication failed: ${(error as Error).message}`);
    }
  }
  
  /**
   * Get authentication headers for requests
   */
  public getAuthHeaders(): Record<string, string> {
    return this.authState.headers || {};
  }
  
  /**
   * Check if current token is expired
   */
  public isTokenExpired(): boolean {
    if (this.authState.type !== 'token' && this.authState.type !== 'oauth2') {
      return false;
    }
    
    if (!this.authState.tokenExpiry) {
      return false;
    }
    
    return new Date() > this.authState.tokenExpiry;
  }
  
  /**
   * Refresh OAuth2 token
   */
  public async refreshOAuth2Token(config: OAuth2Config): Promise<AuthState> {
    if (this.authState.type !== 'oauth2' || !this.authState.refreshToken) {
      throw new Error('No refresh token available');
    }
    
    try {
      const response = await axios.post(config.tokenUrl, new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret || '',
        grant_type: 'refresh_token',
        refresh_token: this.authState.refreshToken
      }), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      
      const { 
        access_token, 
        refresh_token = this.authState.refreshToken, 
        expires_in, 
        token_type = 'Bearer'
      } = response.data;
      
      // Calculate token expiry
      let tokenExpiry: Date | undefined;
      if (expires_in) {
        tokenExpiry = new Date();
        tokenExpiry.setSeconds(tokenExpiry.getSeconds() + expires_in);
      }
      
      // Update auth state
      this.authState = {
        ...this.authState,
        token: access_token,
        refreshToken: refresh_token,
        tokenExpiry,
        oauthTokens: response.data,
        headers: {
          'Authorization': `${token_type} ${access_token}`
        }
      };
      
      return this.getAuthState();
    } catch (error) {
      throw new Error(`Failed to refresh OAuth2 token: ${(error as Error).message}`);
    }
  }
} 