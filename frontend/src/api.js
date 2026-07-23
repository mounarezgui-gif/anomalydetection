// ---- Configuration ----
export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ---- Session (localStorage) ----
export function saveSession(token, user) {
  localStorage.setItem("token", token);
  localStorage.setItem("user", JSON.stringify(user));
}

export function getToken() {
  return localStorage.getItem("token");
}

export function getUser() {
  const raw = localStorage.getItem("user");
  return raw ? JSON.parse(raw) : null;
}

export function clearSession() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
}

// ---- Redirection selon le rôle ----
export function redirectPathFor(user) {
  if (user && user.role === "admin") return "/admin";
  return "/";
}

// ---- Appel générique à l'API ----
export async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_URL}${path}`, { ...options, headers });

  if (response.status === 401 && path !== "/auth/login" && path !== "/auth/register") {
    clearSession();
    window.location.href = "/login";
    throw new Error("Session expirée");
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Une erreur est survenue");
  }
  return data;
}

export async function loginRequest(email, password) {
  const data = await apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  saveSession(data.access_token, data.user);
  return data.user;
}

export async function registerRequest(nom, email, password) {
  const data = await apiFetch("/auth/register", {
    method: "POST",
    body: JSON.stringify({ nom, email, password }),
  });
  saveSession(data.access_token, data.user);
  return data.user;
}

export async function uploadCapture(file) {
  const formData = new FormData();
  formData.append("file", file);
  const token = getToken();
  const res = await fetch(`${API_URL}/analyses`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: formData,
  });
  const body = await res.json();
  if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
  return body;
}
