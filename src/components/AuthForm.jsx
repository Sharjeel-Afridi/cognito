import { useState, useEffect } from "react";
import "../App.css";

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

  // OAuth related states
  const [oauthParams, setOauthParams] = useState(null);

  // API client to handle token refresh
  const apiClient = {
    fetch: async (url, options = {}) => {
      try {
        const tokens = JSON.parse(
          localStorage.getItem("cognitoTokens") || "{}"
        );

        // Add authorization header if we have tokens
        if (tokens.accessToken) {
          options.headers = {
            ...options.headers,
            Authorization: `Bearer ${tokens.accessToken}`,
          };
        }

        const response = await fetch(url, {
          ...options,
          headers: {
            "Content-Type": "application/json",
            ...options.headers,
          },
        });

        // If unauthorized, try to refresh token
        if (response.status === 401 && tokens.refreshToken) {
          try {
            const refreshResponse = await fetch(
              "http://localhost:3001/refresh",
              {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  refreshToken: tokens.refreshToken,
                  username: userData?.username,
                }),
              }
            );

            const refreshData = await refreshResponse.json();

            if (refreshResponse.ok && refreshData.success) {
              // Update tokens in storage
              const updatedTokens = {
                ...tokens,
                accessToken: refreshData.tokens.accessToken,
                idToken: refreshData.tokens.idToken,
                expiresIn: refreshData.tokens.expiresIn,
              };

              localStorage.setItem(
                "cognitoTokens",
                JSON.stringify(updatedTokens)
              );

              // Retry original request with new token
              options.headers = {
                ...options.headers,
                Authorization: `Bearer ${refreshData.tokens.accessToken}`,
              };

              return fetch(url, options);
            } else {
              // If refresh failed, log user out
              localStorage.removeItem("cognitoTokens");
              localStorage.removeItem("cognitoUser");
              setIsLoggedIn(false);
              setUserData(null);
              throw new Error("Session expired. Please log in again.");
            }
          } catch (error) {
            throw error;
          }
        }

        return response;
      } catch (error) {
        console.error("API request error:", error);
        throw error;
      }
    },
  };

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

      setMessage("Please sign in to authorize access to your account");
    }
  }, []);

  // Check if user is already logged in when component mounts
  useEffect(() => {
    const tokens = localStorage.getItem("cognitoTokens");
    const user = localStorage.getItem("cognitoUser");

    if (tokens && user) {
      setIsLoggedIn(true);
      setUserData(JSON.parse(user));

      // Extract roles from ID token if available
      try {
        const parsedTokens = JSON.parse(tokens);
        if (parsedTokens.idToken) {
          // In a real app, you would decode the JWT to get roles
          // For demo, we'll set a placeholder role
          setUserRoles(["User"]);
        }
      } catch (error) {
        console.error("Error parsing tokens:", error);
      }

      // Check if we need to handle OAuth flow for a logged-in user
      if (oauthParams) {
        handleOAuthAuthorization();
      }
    }
  }, [oauthParams]);

  // Function to handle OAuth authorization after login
  const handleOAuthAuthorization = async () => {
    if (!oauthParams || !isLoggedIn) return;

    try {
      // Generate an authorization code and redirect to the callback URL
      // In a real implementation, we'd make a backend request to generate the code

      setMessage("Authorizing application access...");

      // Redirect back to the client application with an authorization code
      const authCode = Math.random().toString(36).substring(2, 15);

      // In a real app, this code would be generated and stored by the backend
      const redirectUrl = new URL(oauthParams.redirect_uri);
      redirectUrl.searchParams.append("code", authCode);
      redirectUrl.searchParams.append("state", oauthParams.state || "");

      // Redirect to the client application
      // window.location.href = redirectUrl.toString();
    } catch (error) {
      console.error("OAuth authorization error:", error);
      setMessage("Authorization failed: " + error.message);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setMessage("");

    try {
      const response = await fetch("http://localhost:3001/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          redirectUri: oauthParams?.redirect_uri, // Pass the redirect URI for OAuth flow
        }),
      });
      const data = await response.json();

      if (response.ok && data.success) {
        if (data.challengeName === "NEW_PASSWORD_REQUIRED") {
          setNewPasswordMode(true);
          setSessionToken(data.session);
          const userAttrs = JSON.parse(
            data.challengeParameters.userAttributes || "{}"
          );
          setChallengeUserData(userAttrs);
          setMessage("Please set a new password to complete your login.");
        }else if (data.tokens) {
          // Normal successful login
          localStorage.setItem("cognitoTokens", JSON.stringify(data.tokens));

          const userInfo = {
            username: username,
            loginTime: new Date().toISOString(),
            email: data.email || username,
          };

          localStorage.setItem("cognitoUser", JSON.stringify(userInfo));

          setIsLoggedIn(true);
          setUserData(userInfo);

          // Handle OAuth flow if needed
          if (oauthParams && data.authorizationCode) {
            // Redirect to the OAuth redirect URI with the authorization code
            const redirectUrl = new URL(oauthParams.redirect_uri);
            redirectUrl.searchParams.append("code", data.authorizationCode);
            redirectUrl.searchParams.append("state", oauthParams.state || "");
            console.log(data);
            console.log(redirectUrl.toString());
            setMessage("Login successful! Redirecting to application...");

            // Redirect after a short delay to ensure message is seen
            setTimeout(() => {
              window.location.href = redirectUrl.toString();
            }, 1000);
          } else {
            setMessage("Login successful!");
          }

          // Clear form
          setUsername("");
          setPassword("");

          // Set default role
          setUserRoles(["User"]);
        }
      } else {
        setMessage(data.error || "Login failed");
      }
    } catch (error) {
      setMessage("An error occurred during login");
      console.error("Login error:", error);
    }
  };

  const handleCompletePasswordChallenge = async (e) => {
    e.preventDefault();

    if (newPassword !== confirmPassword) {
      setMessage("Passwords do not match");
      return;
    }

    try {
      const response = await fetch("http://localhost:3001/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username,
          challengeName: "NEW_PASSWORD_REQUIRED",
          session: sessionToken,
          responses: {
            USERNAME: username,
            NEW_PASSWORD: newPassword,
          },
          redirectUri: oauthParams?.redirect_uri, // Pass the redirect URI for OAuth flow
        }),
      });

      const data = await response.json();

      if (response.ok && data.success && data.tokens) {
        // Store tokens and complete login
        localStorage.setItem("cognitoTokens", JSON.stringify(data.tokens));

        const userInfo = {
          username: username,
          loginTime: new Date().toISOString(),
          email: challengeUserData?.email || username,
        };
        localStorage.setItem("cognitoUser", JSON.stringify(userInfo));

        setIsLoggedIn(true);
        setUserData(userInfo);

        // Handle OAuth flow if needed
        if (oauthParams && data.authorizationCode) {
          // Redirect to the OAuth redirect URI with the authorization code
          const redirectUrl = new URL(oauthParams.redirect_uri);
          redirectUrl.searchParams.append("code", data.authorizationCode);
          redirectUrl.searchParams.append("state", oauthParams.state || "");

          setMessage("Login successful! Redirecting to application...");

          // Redirect after a short delay to ensure message is seen
          setTimeout(() => {
            window.location.href = redirectUrl.toString();
          }, 1000);
        } else {
          setMessage("Login successful!");
        }

        // Reset states
        setNewPasswordMode(false);
        setNewPassword("");
        setConfirmPassword("");
        setUsername("");
        setPassword("");

        // Set default role
        setUserRoles(["User"]);
      } else {
        setMessage(data.error || "Failed to set new password");
      }
    } catch (error) {
      setMessage("Error setting new password");
      console.error("Password challenge error:", error);
    }
  };

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
      setMessage("Logged out successfully");
    }
  };

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
                  <button
                    onClick={handleOAuthAuthorization}
                    className="button button-primary button-block"
                  >
                    Authorize Access
                  </button>
                </div>
              </div>
            )}

            {/* API Test section */}
            <div className="api-test-section">
              <p className="section-title">Test API Endpoints</p>
              <div className="api-buttons">
                <button
                  onClick={async () => {
                    try {
                      const response = await apiClient.fetch(
                        "http://localhost:3001/hello",
                        {
                          method: "POST",
                          body: JSON.stringify({ name: userData?.username }),
                        }
                      );
                      const data = await response.json();
                      setMessage(`API response: ${data.result}`);
                    } catch (error) {
                      setMessage(`Error: ${error.message}`);
                    }
                  }}
                  className="button button-primary"
                >
                  Hello API
                </button>
                <button
                  onClick={async () => {
                    try {
                      const response = await apiClient.fetch(
                        "http://localhost:3001/getuser"
                      );
                      const data = await response.json();
                      setMessage(`User data fetched: ${data.email}`);
                    } catch (error) {
                      setMessage(`Error: ${error.message}`);
                    }
                  }}
                  className="button button-primary"
                >
                  Get User
                </button>
              </div>
            </div>

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
        ) : newPasswordMode ? (
          <div className="new-password-view">
            <div className="auth-header">
              <h2>New Password Required</h2>
              <p className="auth-subheader">
                Please set a new password to continue
              </p>
            </div>

            <form
              className="auth-form"
              onSubmit={handleCompletePasswordChallenge}
            >
              <div className="form-group">
                <label htmlFor="new-password" className="form-label">
                  New Password
                </label>
                <input
                  id="new-password"
                  name="new-password"
                  type="password"
                  required
                  minLength="8"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="confirm-password" className="form-label">
                  Confirm Password
                </label>
                <input
                  id="confirm-password"
                  name="confirm-password"
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <button
                  type="submit"
                  className="button button-primary button-block"
                >
                  Set New Password
                </button>
              </div>
            </form>

            {message && (
              <div
                className={`message ${
                  message.includes("Please set")
                    ? "message-info"
                    : message.includes("success")
                    ? "message-success"
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

            <form className="auth-form" onSubmit={handleLogin}>
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

            {message && (
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
            )}
          </div>
        )}
      </div>
    </div>
  );
}
