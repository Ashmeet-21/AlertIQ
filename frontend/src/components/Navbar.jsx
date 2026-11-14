import { Link, useNavigate } from "react-router-dom";
import { getUser, clearSession } from "../api.js";

const LIVE_LABELS = { connected: "Live", connecting: "Connecting", disconnected: "Offline" };

// wsStatus is only passed by pages that hold a live connection
export default function Navbar({ wsStatus }) {
  const navigate = useNavigate();
  const user = getUser();

  function signOut() {
    clearSession();
    navigate("/login");
  }

  return (
    <header className="topbar">
      <Link to="/" className="wordmark">AlertIQ</Link>
      <div className="topbar-end">
        {wsStatus && (
          <span className="live" data-state={wsStatus} title="New alerts appear without refreshing">
            {LIVE_LABELS[wsStatus] ?? "Offline"}
          </span>
        )}
        <span className="muted">{user.email} ({(user.role ?? "analyst").replace("_", "-")})</span>
        <button className="btn btn-quiet" onClick={signOut}>Sign out</button>
      </div>
    </header>
  );
}
