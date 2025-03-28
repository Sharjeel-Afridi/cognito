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
    ]
  };
  
  try {
    const data = await cognito.adminCreateUser(params).promise();
    
    let authParams = {
      AuthFlow: "USER_PASSWORD_AUTH",
    //   ClientId: appClient, 
      UserPoolId: poolId,
      AuthParameters: {
        USERNAME: attr.username,
        PASSWORD: attr.password
      }
    };
    
    const authResult = await cognito.adminInitiateAuth(authParams).promise();
    
    let challengeResponseData = {
      USERNAME: attr.username,
      NEW_PASSWORD: attr.password
    };
    
    let challengeParams = {
      ChallengeName: "NEW_PASSWORD_REQUIRED",
    //   ClientId: appClient,
      UserPoolId: poolId,
      ChallengeResponses: challengeResponseData,
      Session: authResult.Session
    };
    
    const result = await cognito.adminRespondToAuthChallenge(challengeParams).promise();
    return res.status(200).json({
      success: true,
      data: result
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
};

export const Login = async (req, res) => {
  try {
    const attr = req.body;

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
    
    const result = await cognito.adminInitiateAuth(params).promise();
    res.status(200).json({ 
      success: true,
      data: result
    });
  } catch (err) {
    res.status(401).json({ result: err.message }); 
  }
};

export const LogOut = async (req, res) => {
  try {
    const token = req.header('token').replace('Bearer ', '');
    await cognito.globalSignOut({
      AccessToken: token
    }).promise();
    res.status(200).json({ success: true, data: "Successfully Log Out" });
  } catch (err) {
    res.status(401).json({ result: err.message });
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