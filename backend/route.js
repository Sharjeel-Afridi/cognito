import express from "express";
import {
    Login,
    createCognitoUser,
    LogOut,
    getUser,
    refreshTokens,
    respondToChallenge
} from "./cognitoFunctions.js";

import auth from "./auth/jwtAuth.js";

const router = express.Router();

// Auth Routes
router.post("/login", Login);
router.post("/register", createCognitoUser);
router.post("/logout", LogOut);
router.post("/refresh", refreshTokens);
router.post("/challenge", respondToChallenge);

// Protected Routes
// router.post("/hello", auth.Validate, hello);
// router.get("/getuser", auth.Validate, getUser);

export default router;
