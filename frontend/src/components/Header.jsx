import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import { useAuth } from "../AuthContext";
import { apiFetch } from "../api";

export default function Header() {
  const { user, logout } = useAuth();
  const [apiOk, setApiOk] = useState(null);
  const [theme, setTheme] = useState(() => {
    if (typeof window === "undefined") return "dark";
    return localStorage.getItem("theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  });

  useEffect(() => {
    let mounted = true;
    async function check() {
      try {
        await apiFetch("/analyses");
        if (mounted) setApiOk(true);
      } catch {
        if (mounted) setApiOk(false);
      }
    }
    check();
    const interval = setInterval(check, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  return (
    <header className="app-header">
      <div className="brand">
        <div className="radar"></div>
        <div className="brand-text">
          <div className="eyebrow">Détection comportementale</div>
          <h1>Console d'anomalies réseau</h1>
        </div>
      </div>

      <nav className="nav-links">
        <NavLink to="/" end>Console</NavLink>
        <NavLink to="/conversations">Conversations</NavLink>
        <NavLink to="/alerts">Alertes</NavLink>
      </nav>

      <div className="header-right">
        <button
          type="button"
          className="theme-toggle"
          onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
          aria-label={theme === "dark" ? "Activer le mode clair" : "Activer le mode sombre"}
        >
          <span className="theme-toggle__icon">{theme === "dark" ? "☀️" : "🌙"}</span>
          <span>{theme === "dark" ? "Light mode" : "Dark mode"}</span>
        </button>
        <div className="api-status">
          <span className={`dot ${apiOk === null ? "" : apiOk ? "ok" : "down"}`}></span>
          <span>{apiOk === null ? "connexion..." : apiOk ? "API connectée" : "API injoignable"}</span>
        </div>
        {user && (
          <div className="user-bar">
            <span className="user-name">{user.nom}</span>
            <span className="role-pill">{user.role}</span>
            {user.role === "admin" && <a className="admin-link" href="/admin">Espace admin</a>}
            <button className="logout-btn" onClick={logout}>Déconnexion</button>
          </div>
        )}
      </div>
    </header>
  );
}
