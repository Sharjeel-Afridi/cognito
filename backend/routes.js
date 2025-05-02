import express from "express";

import bodyParser from "body-parser";
import {
  CognitoIdentityProviderClient,
  NotAuthorizedException,
  RespondToAuthChallengeCommand,
  UserNotFoundException,
  InitiateAuthCommand,
  GetUserCommand,
  InvalidParameterException,
  AdminSetUserPasswordCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import CognitoSrpHelper from "cognito-srp-helper";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();
const router = express.Router();


const codeStore = new Map();
const region = process.env.COGNITO_REGION; 
// --- Client Instantiation (Consider Default Provider Chain) ---
const client = new CognitoIdentityProviderClient({
  region: region,
  // credentials: { // Prefer default chain over explicit keys unless necessary
  //   accessKeyId: process.env.ACCESS_KEY,
  //   secretAccessKey: process.env.SECRET_KEY,
  // },
});



export const handleOAuthToken = async (req, res) => {
  try {
    console.log("OAuth token request received");
    // Try to get code from various sources (body or query params)
    const code = req.body.code;

    if (!code) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Authorization code is missing",
      });
    }

    // Look up the stored tokens for this code
    const storedData = codeStore.get(code);

    // Check if the code is valid and not expired
    // here we get the tokens only iof there are tokens associated with that code

    if (!storedData) {
      // Code not found or expired
      codeStore.delete(code); // Clean up if expired
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Authorization code is invalid or expired",
      });
    }

    // Delete the code so it can't be used again (important security practice)
    codeStore.delete(code);

    const expiresIn = Math.floor(
      (storedData.tokens.ExpiresIn - Date.now()) / 1000
    );

    // Return the stored tokens to Rocket Chat
    // return res.status(200).json(storedData.tokens);
    return res.status(200).json({
      access_token: storedData.tokens.AccessToken,
      id_token: storedData.tokens.IdToken,
      refresh_token: storedData.tokens.RefreshToken,
      token_type: "Bearer",
      expires_in: expiresIn > 0 ? expiresIn : 0, // Calculate remaining seconds
    });
  } catch (error) {
    console.error("OAuth token exchange error:", error);
    res.status(400).json({
      error: "invalid_grant",
      error_description: error.message,
    });
  }
};
router.post(
  "/oauth/token",
  bodyParser.urlencoded({ extended: false }),
  handleOAuthToken
);


// OAuth user info endpoint - returns user information using the access token
export const handleUserInfo = async (req, res) => {
  console.log("--- UserInfo Endpoint Hit ---");
  try {
    // 1. Extract Access Token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
      console.log("Missing or invalid Authorization header");
      return res.status(401).set({
         // Required header for OAuth errors
         'WWW-Authenticate': 'Bearer realm="userinfo", error="invalid_token", error_description="Access token is missing or invalid"'
       }).json({
         error: "invalid_token",
         error_description: "Access token is missing or improperly formatted",
       });
    }
    const accessToken = authHeader.substring(7); // Remove "Bearer " prefix

    // 2. Prepare Cognito Client (Assuming 'client' is already instantiated outside)
    // If not, instantiate it here like in the signin route
    // const client = new CognitoIdentityProviderClient({ region: process.env.COGNITO_REGION || process.env.AWS_REGION });

    // 3. Prepare GetUser command
    const getUserParams = {
      AccessToken: accessToken,
    };
    const command = new GetUserCommand(getUserParams);

    // 4. Call Cognito GetUser API
    console.log("--- Calling Cognito GetUser ---");
    const cognitoUser = await client.send(command);
    console.log("--- Cognito GetUser Successful ---", cognitoUser);

    // 5. Map Cognito Attributes to OIDC Standard Claims (or desired format)
    const claims = {};
    // 'sub' (Subject) is usually the Cognito username (unique ID) - REQUIRED
    

    // Map attributes from the UserAttributes array
    if (cognitoUser.UserAttributes && Array.isArray(cognitoUser.UserAttributes)) {
      cognitoUser.UserAttributes.forEach(attr => {
        // Map common standard claims
        switch (attr.Name) {
          case 'sub':
            claims.sub = attr.Value; // Unique identifier for the user
            break;
          case 'email':
            claims.email = attr.Value;
            break;
          case 'email_verified':
            // Convert string "true"/"false" to boolean
            claims.email_verified = attr.Value?.toLowerCase() === 'true';
            break;
          case 'name':
            claims.name = attr.Value || cognitoUser.Username;
            break;
          case 'given_name':
            claims.given_name = attr.Value;
            break;
          case 'family_name':
            claims.family_name = attr.Value;
            break;
          case 'preferred_username':
            // Often same as 'sub' unless explicitly set differently in Cognito
            claims.preferred_username = attr.Value || cognitoUser.Username;
            break;
          case 'phone_number':
            claims.phone_number = attr.Value;
            break;
          case 'phone_number_verified':
            claims.phone_number_verified = attr.Value?.toLowerCase() === 'true';
            break;
          // Add mappings for other standard or custom claims as needed
          // Example for a custom attribute:
          // case 'custom:department':
          //   claims.department = attr.Value;
          //   break;
          default:
            // Optionally include unmapped attributes or ignore
            // claims[attr.Name] = attr.Value; // Be cautious about exposing all attributes
            break;
        }
      });
    }

     // Ensure preferred_username is set if not mapped above
     if (!claims.preferred_username) {
        claims.preferred_username = cognitoUser.Username;
        claims.name = cognitoUser.Username; 
        claims.username = cognitoUser.Username; 
     }

    console.log("--- Returning UserInfo Claims: ---", claims);
    // 6. Return claims as JSON response
    return res.status(200).json(claims);

  } catch (error) {
    console.error("--- UserInfo Endpoint Error ---:", error);

    // Handle specific errors from Cognito GetUser
    if (error.name === 'NotAuthorizedException' || error.name === 'ExpiredCodeException' || error.name === 'InvalidParameterException') {
       // Treat invalid/expired token errors as 401 Unauthorized
       return res.status(401).set({
         'WWW-Authenticate': `Bearer realm="userinfo", error="invalid_token", error_description="${error.message}"`
       }).json({
         error: "invalid_token",
         error_description: `Access token is invalid or expired: ${error.message}`,
       });
    } else if (error.name === 'ResourceNotFoundException') {
        // User associated with token not found - shouldn't happen with valid token but handle defensively
        return res.status(404).json({
            error: "not_found",
            error_description: "User associated with token not found."
        });
    }
    // Handle generic server errors
    return res.status(500).json({
      error: "server_error",
      error_description: "An internal server error occurred.",
    });
  }
};

router.get("/oauth/userinfo", handleUserInfo);

router.post("/api/auth/signin",  async (req, res) => {
   console.log('--- SIGNIN ROUTE HIT (SRP FLOW - Helper Library Wrappers) ---');
   const { username, password } = req.body;
   const clientId = process.env.COGNITO_CLIENT_ID;
   const clientSecret = process.env.COGNITO_CLIENT_SECRET;
   const poolId = process.env.COGNITO_USER_POOL_ID;
   

   
   // --- Validation ---
   if (!username || !password) {
     return res.status(400).json({ message: "Username and password are required." });
   }
   if (!poolId) { return res.status(500).json({ message: 'Server configuration error: Missing User Pool ID.' }); }
   if (!clientId) { return res.status(500).json({ message: 'Server configuration error: Missing Client ID.' }); }
   if (!region) { return res.status(500).json({ message: 'Server configuration error: Missing AWS Region.' }); }

   const poolIdPrefix = poolId.split("_")[0];
   if (!poolIdPrefix) {
     console.error("--- FATAL ERROR: Could not extract prefix from Cognito User Pool ID. ---");
     return res.status(500).json({ message: "Server configuration error." });
   }

   // --- Calculate Secret Hash ---
    let secretHash = null;
    if (clientSecret) {
      secretHash = CognitoSrpHelper.createSecretHash(username, clientId, clientSecret);
      console.log("--- Calculated Secret Hash using helper ---");
    } else {
      console.log("--- No Client Secret found, proceeding without Secret Hash ---");
    }

   try {
        // --- Step 1: Create SRP Session ---
        const srpSession = CognitoSrpHelper.createSrpSession(username, password, poolId, false);
        console.log('--- Created SRP Session ---');

        // --- Step 2: Prepare and Wrap InitiateAuth request ---
        const baseInitiateAuthParams = { /* ... as before ... */
            ClientId: clientId,
            AuthFlow: 'USER_SRP_AUTH',
            AuthParameters: { USERNAME: username, ...(secretHash && { SECRET_HASH: secretHash }) },
        };
        const wrappedInitiateAuthParams = CognitoSrpHelper.wrapInitiateAuth(srpSession, baseInitiateAuthParams);
        console.log('--- Wrapped InitiateAuth Params (SRP_A added by helper) ---');

        // --- Step 3: Send InitiateAuth Command ---
        const initiateCommand = new InitiateAuthCommand(wrappedInitiateAuthParams);
        console.log('--- Attempting InitiateAuth (USER_SRP_AUTH) ---');
        const initiateAuthRes = await client.send(initiateCommand);

        // --- Step 4: Check for PASSWORD_VERIFIER Challenge ---
        if (initiateAuthRes.ChallengeName === 'PASSWORD_VERIFIER') {
          console.log("--- Received PASSWORD_VERIFIER challenge ---");
          const session = initiateAuthRes.Session;

          // --- Step 5: Sign the SRP Session ---
          const signedSrpSession = CognitoSrpHelper.signSrpSession(
            srpSession,
            initiateAuthRes
          );
          console.log("--- Signed SRP Session ---");

          // --- Step 6: Prepare and Wrap RespondToAuthChallenge request ---
          const baseRespondChallengeParams = {
            ClientId: clientId,
            ChallengeName: "PASSWORD_VERIFIER",
            Session: session,
            ChallengeResponses: {
              USERNAME: username,
              ...(secretHash && { SECRET_HASH: secretHash }),
            },
          };
          const wrappedRespondChallengeParams =
            CognitoSrpHelper.wrapAuthChallenge(
              signedSrpSession,
              baseRespondChallengeParams
            );
          console.log(
            "--- Wrapped RespondToAuthChallenge Params (Signature added by helper) ---"
          );

          // --- Step 7: Send RespondToAuthChallenge Command ---
          const respondCommand = new RespondToAuthChallengeCommand(
            wrappedRespondChallengeParams
          );
          console.log("--- Attempting RespondToAuthChallenge ---");
          const respondToAuthChallengeRes = await client.send(respondCommand);

          // --- Step Check Final Response (Modified for IMMEDIATE New Password Test) ---
          if (respondToAuthChallengeRes.AuthenticationResult) {
            // Success Case: Got tokens directly after password verification
            console.log(
              "--- RespondToAuthChallenge Successful - Got Tokens ---"
            );
            const authorizationCode = crypto.randomBytes(32).toString("hex");
            console.log(
              "--- Generated Authorization Code (for testing):",
              authorizationCode
            );
            codeStore.set(authorizationCode, {
              tokens: respondToAuthChallengeRes.AuthenticationResult,
            });
            // console.log(codeStore.get(authorizationCode));

            return res.status(200).json({
              status: "SUCCESS",
              message: "Login successful",
              authorizationCode,
              tokens: respondToAuthChallengeRes.AuthenticationResult,
            });
          } else if (
            respondToAuthChallengeRes.ChallengeName === "NEW_PASSWORD_REQUIRED"
          ) {
            // Challenge Case: New Password Required - Handle Immediately for Testing
            console.log(
              "--- RespondToAuthChallenge requires NEW_PASSWORD_REQUIRED ---"
            );
            console.log(
              "--- !!! Attempting IMMEDIATE response for NEW_PASSWORD_REQUIRED (TESTING ONLY) !!! ---"
            );

            const session = respondToAuthChallengeRes.Session; // Get session for next step

            // --- !!! DEFINE TEST VALUES !!! ---
            const testNewPassword = "Password123$"; // MUST meet your Cognito password policy
            const testRequiredAttributes = {
              // Provide dummy values for required attributes
              email: `test-${username}@example.com`, // Example: Use username to make it somewhat unique
              // Add other required attributes if necessary
            };
            // ---------------------------------

            console.log(
              `--- Setting new password to (TESTING): ${testNewPassword} ---`
            );
            console.log(
              `--- Providing required attributes (TESTING):`,
              testRequiredAttributes
            );

            // Construct ChallengeResponses for the NEW_PASSWORD_REQUIRED challenge
            const newPasswordChallengeResponses = {
              USERNAME: username, // Use original username
              NEW_PASSWORD: testNewPassword,
              ...(secretHash && { SECRET_HASH: secretHash }), // Include hash if needed
            };

            // Add required attributes collected from the user to ChallengeResponses
            for (const key in testRequiredAttributes) {
              // Prefix user attributes as Cognito expects
              newPasswordChallengeResponses[`userAttributes.${key}`] =
                testRequiredAttributes[key];
            }

            // Prepare the second RespondToAuthChallenge command
            const newPasswordRespondParams = {
              ChallengeName: "NEW_PASSWORD_REQUIRED",
              ClientId: clientId,
              Session: session, // Use the session from the NEW_PASSWORD_REQUIRED response
              ChallengeResponses: newPasswordChallengeResponses,
            };

            try {
              // Send the second command to set the new password
              const finalRespondCommand = new RespondToAuthChallengeCommand(
                newPasswordRespondParams
              );
              console.log(
                "--- Attempting 2nd RespondToAuthChallenge (NEW_PASSWORD_REQUIRED) ---"
              );
              const finalResponse = await client.send(finalRespondCommand);

              if (finalResponse.AuthenticationResult) {
                console.log(
                  "--- NEW_PASSWORD_REQUIRED challenge successful via backend test - Got Tokens ---"
                );
                // Send SUCCESS and tokens back to the original caller
                return res.status(200).json({
                  status: "SUCCESS",
                  message: "Login successful (Password auto-set for testing).",
                  tokens: finalResponse.AuthenticationResult,
                });
              } else {
                // This shouldn't happen if the challenge was met correctly
                console.error(
                  "--- ERROR: Auto NEW_PASSWORD_REQUIRED response did not contain tokens ---",
                  finalResponse
                );
                return res
                  .status(500)
                  .json({
                    status: "ERROR",
                    message: "Auto password set, but failed to get tokens.",
                  });
              }
            } catch (newPasswordError) {
              // Catch errors specifically from the second call
              console.error(
                "--- Cognito Error during auto NEW_PASSWORD_REQUIRED:",
                newPasswordError
              );
              let statusCode = 500;
              let message = "Failed to auto-set new password during testing.";
              if (newPasswordError.name === "InvalidPasswordException") {
                statusCode = 400;
                message = `Auto-set password does not meet policy requirements: ${newPasswordError.message}`;
              } else if (newPasswordError.name === "NotAuthorizedException") {
                statusCode = 401;
                message =
                  "Session invalid or expired trying to auto-set password.";
              } // Add other specific error checks

              return res
                .status(statusCode)
                .json({ status: "ERROR", message: message });
            }
          }
          // Add 'else if' blocks here for other challenges like SMS_MFA if needed
          else {
            // Unexpected Case: No tokens and no recognized challenge
            console.error(
              "--- ERROR: RespondToAuthChallenge did not return tokens or known challenge ---",
              respondToAuthChallengeRes
            );
            return res
              .status(500)
              .json({
                status: "ERROR",
                message:
                  "Authentication failed: Unexpected response after challenge.",
              });
          }
          // --- STEPS COMPLETED ---
        } else {
            // Handle case where InitiateAuth did not return PASSWORD_VERIFIER
            console.error('--- ERROR: Unexpected response/challenge from InitiateAuth ---', initiateAuthRes);
            // *** ADD return ***
            return res.status(500).json({ status: 'ERROR', message: `Authentication failed: Unexpected initial response/challenge ${initiateAuthRes.ChallengeName || 'type'}.` });
        }

    } catch (error) {
        // --- Catch block remains the same, already includes 'return' ---
        console.error('--- Cognito Auth Error (SRP Flow with Helper Wrappers):', error);
        let statusCode = 500;
        let message = 'Authentication failed. Please try again later.';
        if (error.name === 'NotAuthorizedException') { statusCode = 401; message = 'Incorrect username or password / Auth failed.'; }
        else if (error.name === 'UserNotFoundException') { statusCode = 404; message = 'User does not exist.'; }
        else if (error.name === 'InvalidParameterException') { statusCode = 400; message = `Authentication failed: Invalid parameters (${error.message})`; }
        else if (error.name === 'UserNotConfirmedException'){ statusCode = 401; message = 'User account is not confirmed. Please check your email or contact support.'; }
        console.log(`--- ERROR: Sending ${statusCode} ---`);
        return res.status(statusCode).json({ message: message }); // Has return
    }
});



// router.post("/logout", async (req, res) => {
//   try {
//     const authHeader = req.header("Authorization");

//     if (!authHeader || !authHeader.startsWith("Bearer ")) {
//       return res.status(400).json({ error: "Access token required" });
//     }

//     const token = authHeader.replace("Bearer ", "");
//     await cognito.logoutUser(token);

//     res.status(200).json({
//       success: true,
//       message: "Successfully logged out",
//     });
//   } catch (error) {
//     console.error("Logout error:", error);
//     res.status(401).json({ error: error.message });
//   }
// });


export default router;
