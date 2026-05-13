/**
 * Navbar
 * Sticky top bar shown on every authenticated page.
 * Shows: logo, WebSocket live status, logged-in user, sign-out button.
 */
import { useNavigate } from "react-router-dom";

function ShieldIcon() {
  return (
    <svg width="24" height="26" viewBox="0 0 24 26" fill="none">
      <path
        d="M12 1L2 5V12C2 18 6.5 23 12 25C17.5 23 22 18 22 12V5L12 1Z"
        fill="rgba(34,211,238,0.1)"
        stroke="var(--cyan)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M8 13l3 3 5-5"
        stroke="var(--cyan)"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Navbar({ wsStatus }) {
  const navigate = useNavigate();

  // Read user from localStorage (set at login)
  const user = (() => {
    try { return JSON.parse(localStorage.getItem("alertiq_user") || "{}"); }
    catch { return {}; }
  })();

  function logout() {
    localStorage.removeItem("alertiq_token");
    localStorage.removeItem("alertiq_user");
    navigate("/login");
  }

  // Dot colour and label depend on WebSocket connection state
  const wsStyles = {
    connected:    { color: "var(--green)",  label: "LIVE"       },
    connecting:   { color: "var(--yellow)", label: "CONNECTING" },
    disconnected: { color: "var(--gray)",   label: "OFFLINE"    },
  };
  const ws = wsStyles[wsStatus] ?? wsStyles.disconnected;

  return (
    <nav className="navbar">
      {/* Left — logo */}
      <span className="navbar__brand" onClick={() => navigate("/")}>
        <ShieldIcon />
        <span className="navbar__logo-text">
          Alert<span className="text-cyan">IQ</span>
        </span>
        <span className="navbar__subtitle">SIEM Triage Platform</span>
      </span>

      {/* Right — status + user + signout */}
      <div className="navbar__end">

        {/* WebSocket status pill */}
        <div className="live-pill" style={{ color: ws.color, borderColor: ws.color + "30" }}>
          <span
            className="live-dot"
            style={{
              background: ws.color,
              boxShadow: wsStatus === "connected" ? `0 0 7px ${ws.color}` : "none",
              animation: wsStatus === "connected" ? "pulse 2s infinite" : "none",
            }}
          />
          {ws.label}
        </div>

        {/* User info pill */}
        <div className="user-pill">
          <div className="user-avatar">
            {(user.email ?? "A")[0].toUpperCase()}
          </div>
          <div>
            <div className="user-email">{user.email ?? "analyst"}</div>
            <div className="user-role">{(user.role ?? "analyst").toUpperCase()}</div>
          </div>
        </div>

        <button className="btn btn-ghost" onClick={logout}>
          Sign out
        </button>
      </div>
    </nav>
  );
}
