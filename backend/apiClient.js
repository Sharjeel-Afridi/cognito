import { refreshTokens } from './authService';

// Create an API client with automatic token refresh
const apiClient = {
  fetch: async (url, options = {}) => {
    // Get the current tokens
    const tokensStr = localStorage.getItem('cognitoTokens');
    let tokens = tokensStr ? JSON.parse(tokensStr) : null;
    
    if (!tokens) {
      throw new Error('No authentication tokens available');
    }
    
    // Prepare headers with authentication
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
      'Authorization': `Bearer ${tokens.accessToken}`
    };
    
    // Make the API request
    let response = await fetch(url, {
      ...options,
      headers
    });
    
    // If the token has expired (401 response)
    if (response.status === 401) {
      try {
        // Get user info for refresh
        const userStr = localStorage.getItem('cognitoUser');
        const user = userStr ? JSON.parse(userStr) : null;
        
        if (!user || !tokens.refreshToken) {
          // Cannot refresh, force logout
          localStorage.removeItem('cognitoTokens');
          localStorage.removeItem('cognitoUser');
          throw new Error('Session expired. Please login again.');
        }
        
        // Try to refresh the token
        const newTokens = await refreshTokens(user.username, tokens.refreshToken);
        
        // Update stored tokens
        localStorage.setItem('cognitoTokens', JSON.stringify(newTokens));
        
        // Retry the original request with new token
        response = await fetch(url, {
          ...options,
          headers: {
            'Content-Type': 'application/json',
            ...options.headers,
            'Authorization': `Bearer ${newTokens.accessToken}`
          }
        });
      } catch (error) {
        // If refresh fails, force logout
        localStorage.removeItem('cognitoTokens');
        localStorage.removeItem('cognitoUser');
        throw new Error('Session expired. Please login again.');
      }
    }
    
    return response;
  }
};

export default apiClient;