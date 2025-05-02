import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import cors from "cors";
import routes from "./routes.js";

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Handle both JSON and form-urlencoded for OAuth endpoints
app.use((req, res, next) => {
  if (
    req.path === "/oauth/token" &&
    req.headers["content-type"]?.includes("application/x-www-form-urlencoded")
  ) {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk.toString();
    });

    req.on("end", () => {
      try {
        const params = new URLSearchParams(data);
        const parsedBody = {};

        for (const [key, value] of params.entries()) {
          parsedBody[key] = value;
        }

        req.body = parsedBody;
      } catch (error) {
        console.error("Failed to parse form data:", error);
      }
      next();
    });
  } else {
    next();
  }
});

// OAuth authorization endpoint
app.get("/oauth/authorize", (req, res) => {
  // Extract and validate OAuth parameters
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  if (!client_id || !redirect_uri || response_type !== "code") {
    return res.status(400).send("Invalid OAuth request parameters");
  }

  // Redirect to the custom login page with OAuth parameters
  const loginUrl = process.env.FRONTEND_URL || "http://localhost:5173/login";

  res.redirect(
    `${loginUrl}?client_id=${client_id}&redirect_uri=${encodeURIComponent(
      redirect_uri
    )}&response_type=${response_type}&scope=${scope || ""}&state=${state || ""}`
  );
});

// API routes
app.use("/", routes);

// Start the server
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`OAuth server running on port ${port}`);
});

export default app;
