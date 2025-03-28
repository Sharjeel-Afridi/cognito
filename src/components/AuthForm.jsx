import { useState } from "react";

export default function AuthForm() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    setMessage("");
  
    try {
      const response = await fetch("http://localhost:3000/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
  
      const text = await response.text(); 
      const data = text ? JSON.parse(text) : {}; 
  
      if (response.ok) {
        setMessage("Login successful!");
      } else {
        setMessage(data.error || "Login failed");
      }
    } catch (error) {
      setMessage("An error occurred.");
    }
  };
  

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form className="p-6 bg-white rounded-lg shadow-md" onSubmit={handleLogin}>
        <h2 className="text-xl font-semibold mb-4">Login</h2>
        <input
          type="text"
          placeholder="Username"
          className="w-full p-2 border rounded mb-2"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="password"
          placeholder="Password"
          className="w-full p-2 border rounded mb-2"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit" className="w-full bg-blue-500 text-white p-2 rounded">
          Login
        </button>
        {message && <p className="mt-2 text-center">{message}</p>}
      </form>
    </div>
  );
}
