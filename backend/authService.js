import apiClient from './apiClient';

export const logout = async (accessToken) => {
  try {
    // Call backend to invalidate the token
    const response = await fetch('http://localhost:3000/api/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      }
    });
    
    if (!response.ok) {
      console.warn('Server-side logout failed, proceeding with local logout');
    }
    
    // Always clear local storage
    localStorage.removeItem('cognitoTokens');
    localStorage.removeItem('cognitoUser');
    
    return true;
  } catch (error) {
    console.error('Logout error:', error);
    
    // Even if server logout fails, clear local storage
    localStorage.removeItem('cognitoTokens');
    localStorage.removeItem('cognitoUser');
    
    return false;
  }
};

export const refreshTokens = async (refreshToken, username) => {
  try {
    const response = await fetch('http://localhost:3000/api/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ refreshToken, username })
    });
    
    if (!response.ok) {
      throw new Error('Failed to refresh tokens');
    }
    
    const result = await response.json();
    return result.tokens;
  } catch (error) {
    console.error('Token refresh failed:', error);
    throw error;
  }
};