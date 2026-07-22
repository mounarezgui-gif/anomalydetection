// ---- Configuration ----
const API_URL = "http://localhost:8000"; // adapte si ton backend tourne ailleurs

// ---- Session ----
function saveSession(token, user) {
  localStorage.setItem("token", token);
  localStorage.setItem("user", JSON.stringify(user));
}

function getToken() {
  return localStorage.getItem("token");
}

function getUser() {
  const raw = localStorage.getItem("user");
  return raw ? JSON.parse(raw) : null;
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  window.location.href = "index.html";
}

// ---- Redirection selon le rôle ----
function redirectPathFor(user) {
  if (user && user.role === "admin") return "admin.html";
  return "index.html";
}

// ---- Appels API ----
async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_URL}${path}`, { ...options, headers });

  if (response.status === 401) {
    // Ne pas déconnecter automatiquement lors d'une tentative de connexion
    // (login/register) : laisser l'appelant afficher l'erreur.
    if (path !== "/auth/login" && path !== "/auth/register") {
      logout();
      throw new Error("Session expirée");
    }
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Une erreur est survenue");
  }
  return data;
}

async function loginRequest(email, password) {
  const data = await apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  saveSession(data.access_token, data.user);
  return data.user;
}

async function registerRequest(nom, email, password) {
  const data = await apiFetch("/auth/register", {
    method: "POST",
    body: JSON.stringify({ nom, email, password }),
  });
  saveSession(data.access_token, data.user);
  return data.user;
}

// ---- Protection des pages ----
// Appelle requireAuth() en haut de alerts.html / conversations.html
// pour bloquer l'accès si non connecté.
function requireAuth() {
  const user = getUser();
  if (!user || !getToken()) {
    window.location.href = "login.html";
    return null;
  }
  return user;
}

// Appelle requireRole("admin") pour une page réservée aux admins.
function requireRole(role) {
  const user = requireAuth();
  if (user && user.role !== role) {
    window.location.href = "index.html";
    return null;
  }
  return user;
}