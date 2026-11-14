import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";

export default function Login() {
  const navigate = useNavigate();
  const [mode, setMode] = useState("login"); // "login" | "register"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      if (mode === "register") {
        await api.register(email, password);
        setSuccess("Account created. Sign in to continue.");
        setMode("login");
        return;
      }
      const { access_token } = await api.login(email, password);
      localStorage.setItem("alertiq_token", access_token);
      localStorage.setItem("alertiq_user", JSON.stringify(await api.me()));
      navigate("/");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function switchMode(next) {
    setMode(next);
    setError("");
    setSuccess("");
  }

  const registering = mode === "register";

  return (
    <main className="signin">
      <span className="wordmark">AlertIQ</span>
      <h1>{registering ? "Create the admin account" : "Sign in"}</h1>
      <p>{registering
        ? "The first account runs this AlertIQ. After that, the admin adds everyone else."
        : "Your alert queue, sorted by what needs a person first."}</p>

      {error && <p className="notice notice-error">{error}</p>}
      {success && <p className="notice notice-ok">{success}</p>}

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" autoComplete="email" value={email}
            onChange={e => setEmail(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" type="password" value={password} minLength={registering ? 8 : undefined}
            autoComplete={registering ? "new-password" : "current-password"}
            onChange={e => setPassword(e.target.value)} required />
        </div>
        <button className="btn" type="submit" disabled={loading}>
          {loading ? "One moment…" : registering ? "Create account" : "Sign in"}
        </button>
      </form>

      <p className="signin-switch">
        {registering ? (
          <>Already have an account? <button className="link-btn" onClick={() => switchMode("login")}>Sign in</button></>
        ) : (
          <>First time setting up AlertIQ? <button className="link-btn" onClick={() => switchMode("register")}>Create the admin account</button></>
        )}
      </p>
    </main>
  );
}
