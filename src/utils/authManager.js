import axios from 'axios';

/**
 * Authentication state interface
 */
export class AuthState {
  constructor() {
    this.type = 'none';
    this.token = undefined;
    this.refreshToken = undefined;
    this.tokenExpiry = undefined;
    this.username = undefined;
    this.password = undefined; // Note: In a production app, we'd use more secure storage
    this.oauthTokens = undefined;
    this.headers = undefined;
  }
}

/**
 * Authentication Manager to handle different auth methods
 */
export class AuthManager {
  static instance;
  authState = new AuthState();
  
  constructor() {
    // Private constructor for singleton pattern
  }
  
  /**
   * Get singleton instance
   */
  static getInstance() {
    if (!AuthManager.instance) {
      AuthManager.instance = new AuthManager();
    }
    return AuthManager.instance;
  }
  
  /**
   * Get current auth state
   */
  getAuthState() {
    return { ...this.authState };
  }
  
  /**
   * Clear auth state
   */
  clearAuth() {
    this.authState = new AuthState();
  }
  
  /**
   * Set token auth
   */
  async setTokenAuth(credentials) {
    const { token, tokenType = 'Bearer', refreshToken, expiresIn } = credentials;
    
    // Calculate token expiry if expiresIn is provided
    let tokenExpiry;
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
  async setBasicAuth(credentials) {
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
  async authenticateWithOAuth2(config) {
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
      let data = {
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
      let tokenExpiry;
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
      throw new Error(`OAuth2 authentication failed: ${error.message}`);
    }
  }
  
  /**
   * Authenticate with a custom API login endpoint
   */
  async authenticateWithApi(
    loginUrl, 
    credentials, 
    options = {}
  ) {
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
      const getNestedValue = (obj, path) => {
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
      let tokenExpiry;
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
      throw new Error(`API authentication failed: ${error.message}`);
    }
  }
  
  /**
   * Get authentication headers for requests
   */
  getAuthHeaders() {
    return this.authState.headers || {};
  }
  
  /**
   * Check if current token is expired
   */
  isTokenExpired() {
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
  async refreshOAuth2Token(config) {
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
      let tokenExpiry;
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
      throw new Error(`Failed to refresh OAuth2 token: ${error.message}`);
    }
  }
}