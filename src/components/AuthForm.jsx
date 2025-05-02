import { useState, useEffect } from "react";
import "../App.css";
// import { SRPCalculator } from "../../backend/SRPcalculator";

export default function AuthForm() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userData, setUserData] = useState(null);
  const [userRoles, setUserRoles] = useState([]);

  const [newPasswordMode, setNewPasswordMode] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [sessionToken, setSessionToken] = useState("");
  const [challengeUserData, setChallengeUserData] = useState(null);
  const [challengeParameters, setChallengeParameters] = useState({});

  // OAuth related states
  const [oauthParams, setOauthParams] = useState(null);


 

  // Parse query parameters from URL
  useEffect(() => {
    const queryParams = new URLSearchParams(window.location.search);

    // Check if we have OAuth parameters in the URL
    const client_id = queryParams.get("client_id");
    const redirect_uri = queryParams.get("redirect_uri");
    const response_type = queryParams.get("response_type");
    const scope = queryParams.get("scope");
    const state = queryParams.get("state");

    // If we have OAuth parameters, store them
    if (client_id && redirect_uri && response_type) {
      setOauthParams({
        client_id,
        redirect_uri,
        response_type,
        scope,
        state,
      });

      // setMessage("Please sign in to authorize access to your account");
    }
  }, []);


  const handleLogout = async () => {
    try {
      const tokens = JSON.parse(localStorage.getItem("cognitoTokens") || "{}");

      if (tokens.accessToken) {
        // Send logout request to backend
        await fetch("http://localhost:3001/logout", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tokens.accessToken}`,
          },
          body: JSON.stringify({
            refreshToken: tokens.refreshToken,
          }),
        });
      }
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      // Always clear local storage and state
      localStorage.removeItem("cognitoTokens");
      localStorage.removeItem("cognitoUser");
      setIsLoggedIn(false);
      setUserData(null);
      setUserRoles([]);
      // setMessage("Logged out successfully");
    }
  };


  const handleSubmit = async (event) => {
    event.preventDefault();

    try {
      // Send plain username/password to YOUR backend (over HTTPS in production)
      const response = await fetch("http://localhost:3001/api/auth/signin", {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username,
          password: password,
        }),
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || 'Login failed');
      }
      if(response.ok){
        const redirectUrl = new URL(oauthParams.redirect_uri);
        redirectUrl.searchParams.append("code", data.authorizationCode);
        redirectUrl.searchParams.append("state", oauthParams.state || "");

        console.log(redirectUrl.toString());

        setTimeout(() => {
          window.location.href = redirectUrl.toString();
        }, 1000);
      }
      // Your backend handled SRP with Cognito. You get tokens back.
      console.log("Login successful:", data);
      localStorage.setItem("accessToken", data.tokens.AccessToken);
      // ... (store other tokens, update UI) ...
      setIsLoggedIn(true);
    } catch (err) {
      // ... (Error Handling as before) ...
      const message = err.message || "Login failed.";
    } finally {

    }
  };

  const handleToken = async () => {
    const tokens = fetch("http://localhost:3001/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: "700d79c6ab563bd14e747e3e07a8990731f7f73db5ac44a8beb36a7faab3f01a",
        state:
          "eyJsb2dpblN0eWxlIjoicmVkaXJlY3QiLCJjcmVkZW50aWFsVG9rZW4iOiJoWjRmbExyX2hVSXlCMTkyQkpzdEdPMnlzZEJaeElJN0dLZDdiem1lTVBlIiwiaXNDb3Jkb3ZhIjpmYWxzZSwicmVkaXJlY3RVcmwiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvaG9tZSJ9",
      }),
    });
    const res = await tokens.json();
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        {isLoggedIn ? (
          <div className="logged-in-view">
            {/* Header with user info */}
            <div className="user-header">
              <div className="user-header-top">
                <h2 className="username">
                  {userData?.fullName || userData?.username}
                </h2>
                <span className="status-badge status-active">Active</span>
              </div>
              <div className="user-details">
                <p>{userData?.email}</p>
                <p>
                  Logged in {new Date(userData?.loginTime).toLocaleString()}
                </p>
              </div>
            </div>

            {/* Roles section */}
            {userRoles.length > 0 && (
              <div className="user-roles">
                <p className="section-title">Roles</p>
                <div className="roles-container">
                  {userRoles.map((role) => (
                    <span key={role} className="role-badge">
                      {role}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* OAuth Authorization section (shown only in OAuth flow) */}
            {oauthParams && (
              <div className="oauth-section">
                <p className="section-title">Authorization Request</p>
                <div className="oauth-details">
                  <p>An application is requesting access to your account:</p>
                  <p>
                    <strong>Client ID:</strong> {oauthParams.client_id}
                  </p>
                  <p>
                    <strong>Scope:</strong>{" "}
                    {oauthParams.scope || "Default Access"}
                  </p>
                  {/* <button
                    onClick={handleOAuthAuthorization}
                    className="button button-primary button-block"
                  >
                    Authorize Access
                  </button> */}
                </div>
              </div>
            )}

            {/* Logout Button */}
            <div className="logout-section">
              <button onClick={handleLogout} className="button button-danger">
                Sign Out
              </button>
            </div>

            {/* Status message */}
            {message && (
              <div
                className={`message ${
                  message.includes("success") || message.includes("fetched")
                    ? "message-success"
                    : message.includes("Redirecting") ||
                      message.includes("Authorizing")
                    ? "message-info"
                    : "message-error"
                }`}
              >
                {message}
              </div>
            )}
          </div>
        ) : (
          <div className="login-view">
            <div className="auth-header">
              <h2>Sign in</h2>
              <p className="auth-subheader">
                {oauthParams
                  ? "Sign in to authorize access to your account"
                  : "Enter your credentials to access your account"}
              </p>
            </div>

            <form className="auth-form" onSubmit={handleSubmit}>
              {/* <form className="auth-form" onSubmit={handleLogin}> */}
              <div className="form-group">
                <label htmlFor="username" className="form-label">
                  Username
                </label>
                <input
                  id="username"
                  name="username"
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="password" className="form-label">
                  Password
                </label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <button
                  type="submit"
                  className="button button-primary button-block"
                >
                  Sign in
                </button>
              </div>
            </form>

            {/* Display OAuth context if applicable */}
            {oauthParams && (
              <div className="oauth-context">
                <p className="oauth-context-title">Authorization Request</p>
                <p>
                  An application with client ID{" "}
                  <strong>{oauthParams.client_id}</strong> is requesting access
                  to your account.
                </p>
                {oauthParams.scope && (
                  <p>
                    Requested permissions: <strong>{oauthParams.scope}</strong>
                  </p>
                )}
              </div>
            )}

            <button
              onClick={handleToken}
              className="button button-primary button-block"
            >
              Tokens
            </button>
            {/* {message && (
              <div
                className={`message ${
                  message.includes("success")
                    ? "message-success"
                    : message.includes("Please sign in to authorize")
                    ? "message-info"
                    : "message-error"
                }`}
              >
                {message}
              </div>
            )} */}
          </div>
        )}
      </div>
      {/* Add this button to your form */}
      {/* <button
        type="button"
        className="mt-2 bg-red-500 text-white p-2 rounded"
        onClick={handlePasswordReset}
      >
        Reset Password
      </button> */}
    </div>
  );
}
