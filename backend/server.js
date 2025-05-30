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



app.get("/oauth/authorize", (req, res) => {
  const frontendURL = "http://localhost:5173/login"; // Your frontend UI
  res.redirect(
    `${frontendURL}?client_id=${req.query.client_id}&redirect_uri=${req.query.redirect_uri}&response_type=code`
  );
});


// Use routes
app.use("/api", routes);

const port = process.env.PORT || 3000;
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
