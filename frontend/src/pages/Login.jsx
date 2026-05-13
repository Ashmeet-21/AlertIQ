/**
 * Login page
 * Split-screen layout:
 *   Left  — product branding + feature highlights
 *   Right — login / register form
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";

// Shield SVG icon used in both panels
function Shield({ size = 40 }) {
  return (
    <svg width={size} height={size * 1.1} viewBox="0 0 40 44" fill="none">
      <path
        d="M20 2L3 9V21C3 31 10.5 40 20 43C29.5 40 37 31 37 21V9L20 2Z"
        fill="rgba(34,211,238,0.1)"
        stroke="var(--cyan)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M13 22l5 5 9-9"
        stroke="var(--cyan)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// Feature item shown in the left panel
function Feature({ icon, title, description }) {
  return (
    <div className="login-feature">
      <div className="login-feature__icon">{icon}</div>
      <div>
        <div className="login-feature__title">{title}</div>
        <div className="login-feature__desc">{description}</div>
      </div>
    </div>
  );
}

export default function Login() {
  const navigate = useNavigate();

  const [mode, setMode]         = useState("login"); // "login" | "register"
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]       = useState("");
  const [success, setSuccess]   = useState("");
  const [loading, setLoading]   = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    try {
      if (mode === "register") {
        await api.register(email, password);
        setSuccess("Account created — you can now sign in.");
        setMode("login");
        return;
      }

      // Login: get token, fetch user, redirect to dashboard
      const { access_token } = await api.login(email, password);
      localStorage.setItem("alertiq_token", access_token);
      const user = await api.me();
      localStorage.setItem("alertiq_user", JSON.stringify(user));
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

  return (
    <div className="login-layout">

      {/* ── Left panel: branding ─────────────────────── */}
      <div className="login-left">
        <div className="login-left__content">

          {/* Logo */}
          <div className="login-branding">
            <Shield size={32} />
            <span className="login-branding__name">
              Alert<span className="text-cyan">IQ</span>
            </span>
          </div>

          {/* Tagline */}
          <h2 className="login-headline">
            AI-Powered<br />Security Triage
          </h2>
          <p className="login-subline">
            Raw security events in. Prioritised, enriched,
            and Claude-triaged verdicts out — in seconds.
          </p>

          {/* Feature list */}
          <div className="login-features">
            <Feature
              icon="⚡"
              title="Real-time pipeline"
              description="Normalise, deduplicate, and enrich every event automatically."
            />
            <Feature
              icon="🤖"
              title="Claude AI verdicts"
              description="Structured triage with confidence scores and recommended actions."
            />
            <Feature
              icon="🔒"
              title="RBAC & audit trail"
              description="Role-based access with analyst feedback fed back into Claude."
            />
          </div>
        </div>

        {/* Bottom version stamp */}
        <div className="login-footer">AlertIQ v1.0 · Steps 1–10 complete</div>
      </div>

      {/* ── Right panel: form ────────────────────────── */}
      <div className="login-right">
        <div className="login-form-wrap fade-in">

          <h1 className="login-form-title">
            {mode === "login" ? "Welcome back" : "Create account"}
          </h1>
          <p className="login-form-subtitle">
            {mode === "login"
              ? "Sign in to access the alert queue."
              : "First account automatically becomes admin."}
          </p>

          <form className="login-form" onSubmit={handleSubmit}>

            <div className="field">
              <label className="field-label">Email address</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="analyst@company.com"
                required
                autoFocus
              />
            </div>

            <div className="field">
              <label className="field-label">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                minLength={6}
              />
            </div>

            {/* Error / success messages */}
            {error   && <div className="alert-msg error">{error}</div>}
            {success && <div className="alert-msg success">{success}</div>}

            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
              style={loading ? { opacity: 0.6, boxShadow: "none" } : {}}
            >
              {loading
                ? "Authenticating…"
                : mode === "login" ? "Sign In" : "Create Account"}
            </button>
          </form>

          {/* Switch between login / register */}
          <p style={{ marginTop: 24, fontSize: 13, color: "var(--muted)", textAlign: "center" }}>
            {mode === "login" ? (
              <>
                No account?{" "}
                <button
                  onClick={() => switchMode("register")}
                  style={{ background: "none", border: "none", color: "var(--cyan)", fontSize: 13, fontWeight: 600, padding: 0 }}
                >
                  Register
                </button>
              </>
            ) : (
              <>
                Already have an account?{" "}
                <button
                  onClick={() => switchMode("login")}
                  style={{ background: "none", border: "none", color: "var(--cyan)", fontSize: 13, fontWeight: 600, padding: 0 }}
                >
                  Sign in
                </button>
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}
