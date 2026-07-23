import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { registerRequest } from "../api";
import { useAuth } from "../AuthContext";

export default function Register() {
  const [nom, setNom] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      // Tout nouveau compte est créé avec le rôle "user" côté serveur.
      const user = await registerRequest(nom, email, password);
      login(user);
      navigate("/");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <p className="auth-eyebrow">Bienvenue</p>
        <h1 className="auth-title">Créer un compte</h1>

        <div className={`auth-error ${error ? "visible" : ""}`}>{error}</div>

        <form onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="nom">Nom</label>
            <input
              id="nom"
              type="text"
              required
              autoComplete="name"
              value={nom}
              onChange={(e) => setNom(e.target.value)}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="password">Mot de passe</label>
            <input
              id="password"
              type="password"
              required
              minLength={6}
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <button className="auth-submit" type="submit" disabled={loading}>
            {loading ? "Création..." : "S'inscrire"}
          </button>
        </form>

        <p className="auth-switch">
          Déjà un compte ? <Link to="/login">Se connecter</Link>
        </p>
      </div>
    </div>
  );
}
