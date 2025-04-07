import dotenv from "dotenv";
dotenv.config();
import AWS from 'aws-sdk';
import fetch from 'node-fetch';
globalThis.fetch = fetch;
import crypto from 'crypto';

// Add console logging to debug
console.log("AWS Access Key available:", !!process.env.ACCESS_KEY);
console.log("AWS Secret Key available:", !!process.env.SECRET_KEY);

AWS.config.update({
  region: process.env.COGNITO_REGION,
  accessKeyId: process.env.ACCESS_KEY,
  secretAccessKey: process.env.SECRET_KEY,
  sessionToken: process.env.SESSION_TOKEN // Optional, if using temporary credentials
});

const cognito = new AWS.CognitoIdentityServiceProvider({ 
  region: process.env.COGNITO_REGION,
  accessKeyId: process.env.ACCESS_KEY,
  secretAccessKey: process.env.SECRET_KEY
});

const poolId = process.env.COGNITO_USER_POOL_ID;
const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const redirectUri = process.env.REDIRECT_URI; // Add this to your .env file

const codeStore = new Map();
// Function to calculate the secret hash
function calculateSecretHash(username) {
  if (!clientSecret) {
    console.error("Client secret is not defined in environment variables");
    throw new Error("Client secret is not configured");
  }
  
  const message = username + clientId;
  const hmac = crypto.createHmac('sha256', clientSecret);
  hmac.update(message);
  
  return hmac.digest('base64');
}

// Login endpoint for direct API calls from your custom UI
export const login = async (req, res) => {
  try {
    const { username, password, redirectUri: requestRedirectUri } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }
    
    // First, validate the user credentials with Cognito using Admin API
    const authParams = {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      UserPoolId: poolId,
      ClientId: clientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
        SECRET_HASH: calculateSecretHash(username)
      }
    };
    
    const authResult = await cognito.adminInitiateAuth(authParams).promise();
    
    // If we have a challenge, return it for the frontend to handle
    if (authResult.ChallengeName) {
      return res.status(200).json({
        success: true,
        challengeName: authResult.ChallengeName,
        session: authResult.Session,
        challengeParameters: authResult.ChallengeParameters,
      });
    }
    
    // If authentication was successful and we have tokens
    if (authResult.AuthenticationResult) {
      const { AccessToken, IdToken, RefreshToken, ExpiresIn } = authResult.AuthenticationResult;
      
      // If we have a redirectUri, we need to generate an authorization code for the OAuth flow
      if (requestRedirectUri) {
        try {
          // This is a simplified approach - in a real implementation, you would:
          // 1. Store the tokens securely on the server
          // 2. Generate a unique authorization code
          // 3. Associate the code with the tokens and a short expiration
          
          // For demonstration purposes, we'll create a random code
          const authorizationCode = crypto.randomBytes(32).toString('hex');
          console.log("Generated authorization code:", authorizationCode);
          
          // Store the code and tokens (in a real app, use a database or secure cache)
          // For example: codeStore.set(authorizationCode, { tokens, expiry: Date.now() + 60000 });
          
          // In a real implementation, you would redirect to the redirectUri with the code
          codeStore.set(authorizationCode, {
          tokens: {
            access_token: AccessToken,
            id_token: IdToken,
            refresh_token: RefreshToken,
            expires_in: ExpiresIn
          },
          expiry: Date.now() + 5 * 60 * 1000 // 5 minutes expiration
        });
          // Here we just return the data to the frontend which will handle the redirect
          return res.status(200).json({
            success: true,
            authorizationCode,
            // Include tokens for your frontend to use directly
            tokens: {
              accessToken: AccessToken,
              idToken: IdToken,
              refreshToken: RefreshToken,
              expiresIn: ExpiresIn
            },
            tokenType: "Bearer"
          });
        } catch (error) {
          console.error("Authorization code generation error:", error);
          return res.status(500).json({ error: "Failed to generate authorization code" });
        }
      } else {
        // Regular login without OAuth flow - just return the tokens
        return res.status(200).json({
          success: true,
          authorizationCode,
          redirectUri: requestRedirectUri,
          tokens: {
            accessToken: AccessToken,
            idToken: IdToken,
            refreshToken: RefreshToken,
            expiresIn: ExpiresIn
          },
          tokenType: "Bearer"
        });
      }
    }
    
    // Should not reach here if auth was successful
    return res.status(401).json({ error: "Authentication failed" });
  } catch (error) {
    console.error("Login error:", error);
    res.status(401).json({ error: error.message });
  }
};



// OAuth endpoints for custom UI integration


// This endpoint handles the OAuth token exchange
export const handleOAuthToken = async (req, res) => {
  try {
  console.log("OAuth token request received");
  console.log("Headers:", req.headers);
  console.log("Body:", req.body);
  console.log("Query:", req.query);
    
    // Try to get code from various sources (body or query params)
    const code = req.body?.code || req.query?.code;
    
    if (!code) {
      return res.status(400).json({ 
        error: "invalid_request", 
        error_description: "Authorization code is missing" 
      });
    }
    
    // Look up the stored tokens for this code
    const storedData = codeStore.get(code); 
    // here we get the tokens only iof there are tokens associated with that code
    
    if (!storedData || Date.now() > storedData.expiry) {
      // Code not found or expired
      codeStore.delete(code); // Clean up if expired
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Authorization code is invalid or expired"
      });
    }
    
    // Delete the code so it can't be used again (important security practice)
    codeStore.delete(code);
    
    // Return the stored tokens to Rocket Chat
    return res.status(200).json(storedData.tokens);
  } catch (error) {
    console.error("OAuth token exchange error:", error);
    res.status(400).json({
      error: "invalid_grant",
      error_description: error.message
    });
  }
};




// OAuth user info endpoint - returns user information from the access token
export const handleUserInfo = async (req, res) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Invalid or missing access token"
      });
    }
    
    const token = authHeader.replace('Bearer ', '');
    
    // Call Cognito to get user information
    try {
      // First try using the SDK method (requires access token)
      const data = await cognito.getUser({ AccessToken: token }).promise();
      
      // Format attributes into a response
      const attributes = Object.fromEntries(
        data.UserAttributes.map(attr => [attr.Name, attr.Value])
      );
      
      return res.status(200).json({
        sub: attributes.sub,
        email: attributes.email,
        email_verified: attributes.email_verified === 'true',
        name: attributes.name || attributes.given_name || data.Username,
        preferred_username: data.Username
      });
    } catch (error) {
      // If direct access fails, try using Cognito's userInfo endpoint
      // This works with ID tokens in OAuth flows
      const userInfoEndpoint = `https://${process.env.COGNITO_DOMAIN}/oauth2/userInfo`;
      
      const response = await fetch(userInfoEndpoint, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to retrieve user information');
      }
      
      const userData = await response.json();
      return res.status(200).json(userData);
    }
  } catch (error) {
    console.error("User info error:", error);
    res.status(401).json({
      error: "invalid_token",
      error_description: error.message
    });
  }
};


// Handle Cognito challenges (like NEW_PASSWORD_REQUIRED)
export const respondToChallenge = async (req, res) => {
  try {
    const { challengeName, session, username, responses, redirectUri: requestRedirectUri } = req.body;
    
    if (!challengeName || !session || !username || !responses) {
      return res.status(400).json({ error: "Missing required challenge parameters" });
    }
    
    // Add the secret hash to the responses
    const challengeResponses = {
      ...responses,
      USERNAME: username,
      SECRET_HASH: calculateSecretHash(username)
    };
    
    const params = {
      ChallengeName: challengeName,
      UserPoolId: poolId,
      ClientId: clientId,
      ChallengeResponses: challengeResponses,
      Session: session
    };
    
    const result = await cognito.adminRespondToAuthChallenge(params).promise();
    
    if (result.AuthenticationResult) {
      const { AccessToken, IdToken, RefreshToken, ExpiresIn } = result.AuthenticationResult;
      
      // Handle OAuth redirect if needed (similar to login endpoint)
      if (requestRedirectUri) {
        const authorizationCode = crypto.randomBytes(32).toString('hex');
        
        return res.status(200).json({
          success: true,
          authorizationCode,
          redirectUri: requestRedirectUri,
          tokens: {
            accessToken: AccessToken,
            idToken: IdToken,
            refreshToken: RefreshToken,
            expiresIn: ExpiresIn
          },
          tokenType: "Bearer"
        });
      } else {
        // Return the tokens directly
        return res.status(200).json({
          success: true,
          tokens: {
            accessToken: AccessToken,
            idToken: IdToken,
            refreshToken: RefreshToken,
            expiresIn: ExpiresIn
          },
          tokenType: "Bearer"
        });
      }
    } else if (result.ChallengeName) {
      // Another challenge is required
      return res.status(200).json({
        success: true,
        challengeName: result.ChallengeName,
        session: result.Session,
        challengeParameters: result.ChallengeParameters,
      });
    }
    
    // Should not reach here if auth was successful
    return res.status(401).json({ error: "Authentication failed" });
  } catch (error) {
    console.error("Challenge response error:", error);
    res.status(401).json({ error: error.message });
  }
};

// Refresh tokens using the refresh token
export const refreshTokens = async (req, res) => {
  try {
    const { refreshToken, username } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }
    
    // Using the refreshToken to get new access and ID tokens
    const params = {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
        SECRET_HASH: username ? calculateSecretHash(username) : undefined
      }
    };
    
    // Use the initiateAuth API for refresh token flow
    const result = await cognito.initiateAuth(params).promise();
    
    if (result.AuthenticationResult) {
      return res.status(200).json({
        success: true,
        tokens: {
          accessToken: result.AuthenticationResult.AccessToken,
          idToken: result.AuthenticationResult.IdToken,
          expiresIn: result.AuthenticationResult.ExpiresIn
        },
        tokenType: "Bearer"
      });
    } else {
      return res.status(401).json({ error: "Failed to refresh tokens" });
    }
  } catch (error) {
    console.error("Token refresh error:", error);
    res.status(401).json({ error: error.message });
  }
};

// Create a user in Cognito (admin function)
export const createCognitoUser = async (req, res) => {
  const attr = req.body;
  let params = {
    UserPoolId: poolId,
    Username: attr.username,
    MessageAction: "SUPPRESS",
    TemporaryPassword: attr.password,
    UserAttributes: [
      {
        Name: "email",
        Value: attr.email
      },
      {
        Name: "name",
        Value: attr.name
      },
      {
        Name: "email_verified",
        Value: "true"
      }
    ]
  };
  
  try {
    // Create the user
    const data = await cognito.adminCreateUser(params).promise();
    
    // Set the user's password permanently (skip the force change password challenge)
    const setPasswordParams = {
      Password: attr.password,
      Permanent: true,
      UserPoolId: poolId,
      Username: attr.username
    };
    
    await cognito.adminSetUserPassword(setPasswordParams).promise();
    
    return res.status(200).json({
      success: true,
      message: "User created successfully",
      user: data.User
    });
  } catch (error) {
    console.error("User creation error:", error);
    return res.status(400).json({ error: error.message });
  }
};

// Get the current user's information
export const getUser = async (req, res) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "") || req.query.token;
    
    if (!token) {
      return res.status(400).json({ error: "Access token required" });
    }
    
    // Get user details from Cognito
    const data = await cognito.getUser({ AccessToken: token }).promise();
    
    // Extract necessary user attributes
    const attributes = Object.fromEntries(
      data.UserAttributes.map(attr => [attr.Name, attr.Value])
    );
    
    res.status(200).json({
      id: attributes.sub,
      username: data.Username,
      email: attributes.email,
      name: attributes.name || "No Name"
    });
  } catch (error) {
    console.error("Get user error:", error);
    res.status(401).json({ error: error.message });
  }
};

// Log the user out
export const logOut = async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.headers.authorization?.replace('Bearer ', '') || 
                  req.query.token;
    
    if (!token) {
      return res.status(400).json({ error: "Access token required" });
    }
    
    // Get the user's refresh token (you might need to get this from your frontend)
    const refreshToken = req.body.refreshToken;
    
    // Revoke the refresh token if provided
    if (refreshToken) {
      try {
        // Revoking refresh tokens requires calling the Cognito token endpoint
        const revokeEndpoint = `https://${process.env.COGNITO_DOMAIN}/oauth2/revoke`;
        
        const authorization = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
        
        await fetch(revokeEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${authorization}`
          },
          body: new URLSearchParams({
            token: refreshToken,
            client_id: clientId
          })
        });
      } catch (error) {
        console.error("Refresh token revocation error:", error);
        // Continue with logout even if refresh token revocation fails
      }
    }
    
    // Sign the user out globally (invalidate all tokens)
    try {
      await cognito.globalSignOut({
        AccessToken: token
      }).promise();
    } catch (error) {
      console.error("Global sign out error:", error);
      
      // If the error is due to an invalid token, still report success
      if (error.code === 'NotAuthorizedException') {
        return res.status(200).json({ 
          success: true, 
          message: "Session already expired" 
        });
      }
      
      // For other errors, continue if possible
    }
    
    res.status(200).json({ 
      success: true, 
      message: "Successfully logged out" 
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(401).json({ error: error.message });
  }
};

// Endpoint to generate the logout URL for the Cognito hosted UI
export const getLogoutUrl = (req, res) => {
  try {
    const { redirectUri } = req.query;
    
    const cognitoDomain = process.env.COGNITO_DOMAIN;
    const logoutRedirectUri = redirectUri || process.env.LOGOUT_REDIRECT_URI;
    
    if (!cognitoDomain) {
      return res.status(400).json({ error: "Cognito domain is not configured" });
    }
    
    if (!logoutRedirectUri) {
      return res.status(400).json({ error: "Logout redirect URI is not specified" });
    }
    
    const logoutUrl = new URL(`https://${cognitoDomain}/logout`);
    logoutUrl.searchParams.append('client_id', clientId);
    logoutUrl.searchParams.append('logout_uri', logoutRedirectUri);
    
    res.status(200).json({ 
      success: true, 
      logoutUrl: logoutUrl.toString() 
    });
  } catch (error) {
    console.error("Error generating logout URL:", error);
    res.status(500).json({ error: error.message });
  }
};

// Simple health check endpoint
export const hello = (req, res) => {
  try {
    const user = req.body.name || "Guest";
    res.status(200).json({ result: `Hello, ${user}!` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};