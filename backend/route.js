import express from "express";
import {
  createCognitoUser,
  login,
  refreshTokens,
  respondToChallenge,
  getUser,
  logOut,
  getLogoutUrl,
  hello,
  handleOAuthToken,
  handleUserInfo
} from "./cognitoFunctions.js";

const router = express.Router();

// User management routes
router.post("/create", createCognitoUser);
router.post("/login", login);
router.post("/refresh", refreshTokens);
router.post("/challenge", respondToChallenge);
router.get("/oauth/userinfo", getUser);
router.post("/logout", logOut);
router.get("/logout-url", getLogoutUrl);
router.post("/hello", hello);

// OAuth endpoints
router.post("/oauth/token", handleOAuthToken);
router.get("/oauth/userinfo", handleUserInfo);

export default router;