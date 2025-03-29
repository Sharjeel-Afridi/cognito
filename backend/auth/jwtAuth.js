import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";
import request from "request";
import { promisify } from "util";

// Create an object with methods
const auth = {
  Validate: function(req, res, next) {
    // Get the token from the Authorization header
    const token = req.headers.authorization?.replace("Bearer ", "") || 
                  req.header("token")?.replace("Bearer ", "");
    
    if (!token) {
      return res.status(401).json({ error: "Access token required" });
    }
    
    // Fetch the JSON Web Key Set (JWKS) from Cognito
    request({
      url: `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
      json: true
    }, function(error, response, body) {
      if (error || response.statusCode !== 200) {
        console.error("Error fetching JWKS:", error || response.statusCode);
        return res.status(500).json({ error: "Authentication service unavailable" });
      }

      try {
        // Decode the token without verification to get the kid
        const decodedJwt = jwt.decode(token, { complete: true });
        
        if (!decodedJwt) {
          return res.status(401).json({ error: "Invalid token format" });
        }
        
        // Get the key ID from the token header
        const kid = decodedJwt.header.kid;
        
        // Find the matching key in the JWKS
        const key = body.keys.find(k => k.kid === kid);
        
        if (!key) {
          return res.status(401).json({ error: "Invalid token key" });
        }
        
        // Convert the JWK to PEM format
        const pem = jwkToPem({
          kty: key.kty,
          n: key.n,
          e: key.e
        });
        
        // Verify the token
        jwt.verify(
          token, 
          pem, 
          { 
            issuer: `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`,
            maxAge: '1h' // Token expiry check
          },
          (err, payload) => {
            if (err) {
              console.error("Token verification failed:", err.message);
              
              // Handle specific token errors
              if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: "Token expired", code: "TOKEN_EXPIRED" });
              }
              
              return res.status(401).json({ error: "Invalid token" });
            }
            
            // Check for required scopes if needed
            // if (!payload.scope || !payload.scope.includes('required_scope')) {
            //   return res.status(403).json({ error: "Insufficient permissions" });
            // }
            
            // Add the user data to the request object
            req.user = {
              sub: payload.sub,
              username: payload['cognito:username'],
              email: payload.email,
              groups: payload['cognito:groups'] || []
            };
            
            next();
          }
        );
      } catch (err) {
        console.error("Token validation error:", err);
        return res.status(401).json({ error: "Invalid token" });
      }
    });
  },
  
  // Add a middleware to check for specific roles/groups
  CheckRole: function(allowedRoles) {
    return function(req, res, next) {
      // First ensure the user is authenticated
      if (!req.user) {
        return res.status(401).json({ error: "Authentication required" });
      }
      
      // Check if the user has one of the allowed roles/groups
      const userGroups = req.user.groups || [];
      const hasPermission = allowedRoles.some(role => userGroups.includes(role));
      
      if (!hasPermission) {
        return res.status(403).json({ error: "Insufficient permissions" });
      }
      
      next();
    };
  }
};

export default auth;