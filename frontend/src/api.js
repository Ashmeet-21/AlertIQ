/**
 * Thin API wrapper.
 * - All requests go to localhost:8000 (the FastAPI backend).
 * - JWT is read from localStorage and injected as Authorization header.
 * - 401 → clear token + redirect to /login.
 */

const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

function authHeaders() {
  const token = localStorage.getItem("alertiq_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function apiFetch(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });

  if (res.status === 401) {
    localStorage.removeItem("alertiq_token");
    localStorage.removeItem("alertiq_user");
    window.location.href = "/login";
    return;
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || "API error");
  }

  // 204 No Content
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  // Auth
  login: (email, password) =>
    apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  register: (email, password) =>
    apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  me: () => apiFetch("/auth/me"),

  // Alerts
  alerts: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, v]) => v != null))
    ).toString();
    return apiFetch(`/alerts${qs ? "?" + qs : ""}`);
  },

  alert: (id) => apiFetch(`/alerts/${id}`),

  stats: () => apiFetch("/alerts/stats"),

  submitVerdict: (id, analyst_verdict, analyst_notes) =>
    apiFetch(`/alerts/${id}/verdict`, {
      method: "PATCH",
      body: JSON.stringify({ analyst_verdict, analyst_notes }),
    }),

  // Health
  health: () => apiFetch("/health"),
};

/**
 * Create a WebSocket connection to the backend.
 * Returns the native WebSocket object — caller must manage onmessage/onclose.
 */
export function createAlertSocket() {
  const wsBase = BASE.replace("http://", "ws://").replace("https://", "wss://");
  return new WebSocket(`${wsBase}/ws/alerts`);
}
