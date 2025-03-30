import { useState, useEffect } from "react";

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

  // Create API client to handle token refresh
  const apiClient = {
    fetch: async (url, options = {}) => {
      try {
        const tokens = JSON.parse(localStorage.getItem("cognitoTokens") || "{}");
        
        // Add authorization header if we have tokens
        if (tokens.accessToken) {
          options.headers = {
            ...options.headers,
            "Authorization": `Bearer ${tokens.accessToken}`
          };
        }
        
        const response = await fetch(url, {
          ...options,
          headers: {
            "Content-Type": "application/json",
            ...options.headers
          }
        });
        
        // If unauthorized, try to refresh token
        if (response.status === 401 && tokens.refreshToken) {
          try {
            const refreshResponse = await fetch("http://localhost:3000/api/refresh", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ 
                refreshToken: tokens.refreshToken,
                username: userData?.username
              })
            });
            
            const refreshData = await refreshResponse.json();
            
            if (refreshResponse.ok && refreshData.success) {
              // Update tokens in storage
              const updatedTokens = {
                ...tokens,
                accessToken: refreshData.tokens.accessToken,
                idToken: refreshData.tokens.idToken,
                expiresIn: refreshData.tokens.expiresIn
              };
              
              localStorage.setItem("cognitoTokens", JSON.stringify(updatedTokens));
              
              // Retry original request with new token
              options.headers = {
                ...options.headers,
                "Authorization": `Bearer ${refreshData.tokens.accessToken}`
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
    }
  };

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
    }
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setMessage("");

    try {
        const queryParams = new URLSearchParams(window.location.search);
        const redirectUri = queryParams.get("redirect_uri");
        
        const response = await fetch("http://localhost:3000/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ 
            username, 
            password,
            redirectUri // Include redirectUri in request
          }),
        });

        const data = await response.json();

        if (response.ok && data.success) {
          if (data.challengeName === "NEW_PASSWORD_REQUIRED") {
            setNewPasswordMode(true);
            setSessionToken(data.session);
            const userAttrs = JSON.parse(data.challengeParameters.userAttributes);
            setChallengeUserData(userAttrs);
            setMessage("Please set a new password to complete your login.");
            
            // Store redirectUri for use after challenge is completed
            if (data.redirectUri) {
              localStorage.setItem("pendingRedirectUri", data.redirectUri);
            }
          } else if (data.tokens) {
            // Normal successful login
            localStorage.setItem("cognitoTokens", JSON.stringify(data.tokens));
            
            const userInfo = {
              username: username,
              loginTime: new Date().toISOString(),
              email: data.email
            };
            
            localStorage.setItem("cognitoUser", JSON.stringify(userInfo));
            
            setIsLoggedIn(true);
            setUserData(userInfo);
            
            // Handle redirect if redirectUri exists in the response
            if (data.redirectUri) {
              const handleRedirect = () => {
                
                window.location.href = `${data.redirectUri}#access_token=${response.tokens.accessToken}&token_type=Bearer`;
                
              };
              
              // Redirect after a short delay to ensure state is updated
              setTimeout(handleRedirect, 300);
              setMessage("Login successful! Redirecting...");
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
          setMessage(data.result || "Login failed");
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
      const response = await fetch("http://localhost:3000/api/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username,
          challengeName: "NEW_PASSWORD_REQUIRED",
          session: sessionToken,
          responses: {
            USERNAME: username,
            NEW_PASSWORD: newPassword
          }
        }),
      });

      const data = await response.json();

      if (response.ok && data.success && data.tokens) {
        // Store tokens and complete login
        localStorage.setItem("cognitoTokens", JSON.stringify(data.tokens));
        
        const userInfo = {
          username: username,
          loginTime: new Date().toISOString(),
          email: challengeUserData?.email
        };
        localStorage.setItem("cognitoUser", JSON.stringify(userInfo));
        
        setIsLoggedIn(true);
        setUserData(userInfo);
        setMessage("Login successful!");
        
        // Reset states
        setNewPasswordMode(false);
        setNewPassword("");
        setConfirmPassword("");
        setUsername("");
        setPassword("");
        
        // Set default role
        setUserRoles(["User"]);
      } else {
        setMessage(data.result || "Failed to set new password");
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
        await fetch("http://localhost:3000/api/logout", {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            "Authorization": `Bearer ${tokens.accessToken}`
          }
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
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 p-4">
      {isLoggedIn ? (
        <div className="p-6 bg-white rounded-lg shadow-md w-full max-w-md">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold">Welcome, {userData?.fullName || userData?.username}</h2>
            <div className="bg-green-500 text-white text-xs px-2 py-1 rounded-full">Logged In</div>
          </div>
          
          <div className="text-sm text-gray-600 mb-4">
            <p className="mb-1"><span className="font-semibold">Username:</span> {userData?.username}</p>
            {userData?.email && (
              <p className="mb-1"><span className="font-semibold">Email:</span> {userData.email}</p>
            )}
            <p className="mb-1"><span className="font-semibold">Login time:</span> {new Date(userData?.loginTime).toLocaleString()}</p>
            
            {userRoles.length > 0 && (
              <div className="mt-2">
                <p className="font-semibold">Your roles:</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {userRoles.map(role => (
                    <span key={role} className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">
                      {role}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          {/* Test protected endpoints */}
          <div className="mb-4 p-3 border rounded">
            <h3 className="font-medium mb-2">Test Protected Endpoints</h3>
            <div className="flex gap-2">
              <button 
                onClick={async () => {
                  try {
                    const response = await apiClient.fetch("http://localhost:3000/api/hello", {
                      method: "POST",
                      body: JSON.stringify({ name: userData?.username })
                    });
                    const data = await response.json();
                    setMessage(`API response: ${data.result}`);
                  } catch (error) {
                    setMessage(`Error: ${error.message}`);
                  }
                }}
                className="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm"
              >
                Hello API
              </button>
              <button 
                onClick={async () => {
                  try {
                    const response = await apiClient.fetch("http://localhost:3000/api/getuser");
                    const data = await response.json();
                    setMessage(`User data fetched: ${data.data}`);
                  } catch (error) {
                    setMessage(`Error: ${error.message}`);
                  }
                }}
                className="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm"
              >
                Get User
              </button>
            </div>
          </div>
          
          <button 
            onClick={handleLogout} 
            className="w-full bg-red-500 hover:bg-red-600 text-white p-2 rounded transition"
          >
            Logout
          </button>
          
          {message && (
            <p className={`mt-3 text-center text-sm ${message.includes("success") ? "text-green-600" : "text-red-600"}`}>
              {message}
            </p>
          )}
        </div>
      ) : newPasswordMode ? (
        <form className="p-6 bg-white rounded-lg shadow-md w-full max-w-md" onSubmit={handleCompletePasswordChallenge}>
          <h2 className="text-xl font-semibold mb-2">Set New Password</h2>
          <p className="text-sm text-gray-600 mb-4">
            Your account requires a password reset to continue.
          </p>
          
          <input
            type="password"
            placeholder="New Password"
            className="w-full p-2 border rounded mb-2"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            minLength="8"
          />
          
          <input
            type="password"
            placeholder="Confirm New Password"
            className="w-full p-2 border rounded mb-4"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
          
          <button 
            type="submit" 
            className="w-full bg-blue-500 hover:bg-blue-600 text-white p-2 rounded transition"
          >
            Set New Password
          </button>
          
          {message && (
            <p className={`mt-3 text-center text-sm ${message.includes("Please set") ? "text-blue-600" : message.includes("success") ? "text-green-600" : "text-red-600"}`}>
              {message}
            </p>
          )}
        </form>
      ) : (
        <form className="p-6 bg-white rounded-lg shadow-md w-full max-w-md" onSubmit={handleLogin}>
          <h2 className="text-xl font-semibold mb-4">Login</h2>
          <input
            type="text"
            placeholder="Username"
            className="w-full p-2 border rounded mb-2"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Password"
            className="w-full p-2 border rounded mb-4"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button 
            type="submit" 
            className="w-full bg-blue-500 hover:bg-blue-600 text-white p-2 rounded transition"
          >
            Login
          </button>
          {message && (
            <p className={`mt-3 text-center text-sm ${message.includes("success") ? "text-green-600" : "text-red-600"}`}>
              {message}
            </p>
          )}
        </form>
      )}
    </div>
  );
}