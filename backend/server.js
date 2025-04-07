import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();
import cors from "cors";
import routes from "./route.js";

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));  // For application/x-www-form-urlencoded

// Raw body parser fallback for debugging
app.use((req, res, next) => {
  if (req.path === '/oauth/token' && !req.body) {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
    });
    
    req.on('end', () => {
      try {
        // Try to parse as URL-encoded
        const params = new URLSearchParams(data);
        const parsedBody = {};
        
        for (const [key, value] of params.entries()) {
          parsedBody[key] = value;
        }
        
        req.body = parsedBody;
        console.log("Manually parsed body:", req.body);
      } catch (e) {
        console.error("Failed to manually parse body:", e);
      }
      next();
    });
  } else {
    next();
  }
});
// OAuth endpoints - these are the entry points for the OAuth flow
// Cognito will redirect to /oauth/authorize when authentication is needed

// This route handles the initial OAuth authorization request from Rocket Chat
app.get("/oauth/authorize", (req, res) => {

  // http://localhost:3001/oauth/authorize?client_id=rocket.chat&redirect_uri=http://localhost:3000/oauth/callback&response_type=code&scope=openid&state=xyz
  // Extract OAuth parameters
  const { client_id, redirect_uri, response_type, scope, state } = req.query;
  
  // Validate required parameters
  if (!client_id || !redirect_uri || !response_type) {
    return res.status(400).send("Invalid OAuth request parameters");
  }
  
  // Redirect to your custom login page with the OAuth parameters
  const frontendURL = process.env.FRONTEND_LOGIN_URL || "http://localhost:5173/login";
  
  // Pass all the OAuth parameters to your custom login UI
  // http://localhost:5173/login?client_id=rocket.chat&redirect_uri=http://localhost:3000/oauth/callback&response_type=code&scope=openid&state=xyz
  res.redirect(
    `${frontendURL}?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=${response_type}&scope=${scope || ''}&state=${state || ''}`
  );
});

// Use API routes
app.use("/", routes);

const port = process.env.PORT || 3001;
const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Handle errors
if (typeof process !== "undefined" && process.on) {
  process.on("unhandledRejection", (error) => {
    console.log("UnhandledRejection:", error.message);
    server.close(() => process.exit(1));
  });
} else {
  console.error(
    "UnhandledRejection handling is not supported in this environment."
  );
}

export default app;