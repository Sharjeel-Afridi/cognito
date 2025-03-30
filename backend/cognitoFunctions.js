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
  secretAccessKey: process.env.SECRET_KEY
});

const cognito = new AWS.CognitoIdentityServiceProvider({ 
  region: process.env.COGNITO_REGION
});

const poolId = process.env.COGNITO_USER_POOL_ID;
const appClient = process.env.COGNITO_CLIENT_ID;

// Function to calculate the secret hash
function calculateSecretHash(username) {
    const clientSecret = process.env.COGNITO_CLIENT_SECRET;
    const clientId = process.env.COGNITO_CLIENT_ID;
    
    if (!clientSecret) {
      console.error("Client secret is not defined in environment variables");
      throw new Error("Client secret is not configured");
    }
    
    const message = username + clientId;
    const hmac = crypto.createHmac('sha256', clientSecret);
    hmac.update(message);
    
    return hmac.digest('base64');
  }

// The rest of your code remains unchanged
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
      ],
      SecretHash: calculateSecretHash(attr.username)
    };
    
    try {
      const data = await cognito.adminCreateUser(params).promise();
      
      let authParams = {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        UserPoolId: poolId,
        AuthParameters: {
          USERNAME: attr.username,
          PASSWORD: attr.password,
          SECRET_HASH: calculateSecretHash(attr.username)
        }
      };
      
      const authResult = await cognito.adminInitiateAuth(authParams).promise();
      
      if (authResult.ChallengeName === "NEW_PASSWORD_REQUIRED") {
        let challengeResponseData = {
          USERNAME: attr.username,
          NEW_PASSWORD: attr.password,
          SECRET_HASH: calculateSecretHash(attr.username)
        };
        
        let challengeParams = {
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          UserPoolId: poolId,
          ChallengeResponses: challengeResponseData,
          Session: authResult.Session
        };
        
        const result = await cognito.adminRespondToAuthChallenge(challengeParams).promise();
        
        // Return the full token set
        const { AccessToken, IdToken, RefreshToken, ExpiresIn } = result.AuthenticationResult;
        
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
      } else {
        return res.status(200).json({
          success: true,
          data: authResult
        });
      }
    } catch (error) {
      console.error("User creation error:", error);
      return res.status(400).json({ error: error.message });
    }
  };

export const Login = async (req, res) => {
  try {
    const attr = req.body;
    
    const redirectUri = attr.redirectUri;
    
    let params = {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      ClientId: appClient, 
      UserPoolId: poolId,
      AuthParameters: {
        USERNAME: attr.username,
        PASSWORD: attr.password,
        SECRET_HASH: calculateSecretHash(attr.username)
      }
    };
    
    const authResult = await cognito.adminInitiateAuth(params).promise();
    
    // Check if we have tokens
    if (authResult.AuthenticationResult) {
      // We have tokens already (for known users)
      const { AccessToken, IdToken, RefreshToken, ExpiresIn } = authResult.AuthenticationResult;
      
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
    else if (authResult.ChallengeName) {
      // Handle challenges like NEW_PASSWORD_REQUIRED
      return res.status(200).json({
        success: true,
        challengeName: authResult.ChallengeName,
        session: authResult.Session,
        challengeParameters: authResult.ChallengeParameters
      });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(401).json({ result: err.message }); 
  }
};

export const refreshTokens = async (req, res) => {
    try {
      const refreshToken = req.body.refreshToken;
      
      if (!refreshToken) {
        return res.status(400).json({ result: "Refresh token is required" });
      }
      
      const params = {
        AuthFlow: "REFRESH_TOKEN_AUTH",
        ClientId: appClient,
        AuthParameters: {
          REFRESH_TOKEN: refreshToken,
          SECRET_HASH: calculateSecretHash(req.body.username)
        }
      };
      
      // Note: For refreshing, we use initiateAuth (client API), not adminInitiateAuth
      const result = await cognito.initiateAuth(params).promise();
      
      return res.status(200).json({
        success: true,
        tokens: {
          accessToken: result.AuthenticationResult.AccessToken,
          idToken: result.AuthenticationResult.IdToken,
          expiresIn: result.AuthenticationResult.ExpiresIn
        },
        tokenType: "Bearer"
      });
    } catch (err) {
      console.error("Token refresh error:", err);
      res.status(401).json({ result: err.message });
    }
  };

  export const respondToChallenge = async (req, res) => {
    try {
      const { challengeName, session, username, responses } = req.body;
      
      if (!challengeName || !session || !username || !responses) {
        return res.status(400).json({ 
          result: "Missing required challenge parameters" 
        });
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
        ClientId: appClient, 
        ChallengeResponses: challengeResponses,
        Session: session
      };
      
      const result = await cognito.adminRespondToAuthChallenge(params).promise();
      
      if (result.AuthenticationResult) {
        // Return the full token set
        const { AccessToken, IdToken, RefreshToken, ExpiresIn } = result.AuthenticationResult;
        
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
      } else if (result.ChallengeName) {
        // Another challenge is required
        return res.status(200).json({
          success: true,
          challengeName: result.ChallengeName,
          session: result.Session,
          challengeParameters: result.ChallengeParameters
        });
      }
    } catch (err) {
      console.error("Challenge response error:", err);
      res.status(401).json({ result: err.message });
    }
  };

  export const LogOut = async (req, res) => {
    try {
      const token = req.header('token')?.replace('Bearer ', '') || 
                    req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        return res.status(400).json({ error: "Access token required" });
      }
      
      // Global sign out invalidates all of the user's tokens
      await cognito.globalSignOut({
        AccessToken: token
      }).promise();
      
      res.status(200).json({ 
        success: true, 
        message: "Successfully logged out from all devices" 
      });
    } catch (err) {
      console.error("Logout error:", err);
      
      // Check if the error is due to an invalid token
      if (err.code === 'NotAuthorizedException') {
        // For expired tokens, still report success since the user is effectively logged out
        return res.status(200).json({ 
          success: true, 
          message: "Session already expired" 
        });
      }
      
      res.status(401).json({ error: err.message });
    }
  };

export const getUser = async (req, res) => {
  try {
    const token = req.header('token').replace('Bearer ', '');
    let data = await cognito.getUser({
      AccessToken: token
    }).promise();
    res.status(200).json({ data: data.Username, user: data.UserAttributes });
  } catch (err) {
    res.status(401).json({ result: err.message });
  }
};

export const hello = (req, res) => {
  try {
    const user = req.body.name;
    res.status(200).json({ result: user });
  } catch (error) {
    res.send(error);
  }
};