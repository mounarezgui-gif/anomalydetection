import { useEffect, useState } from "react";
import Header from "../components/Header";
import { apiFetch } from "../api";

function sevBadge(sev) {
  return <span className={`sev-badge sev-${sev}`}>{sev}</span>;
}

export default function Alerts() {
  const [analyses, setAnalyses] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    apiFetch("/analyses")
      .then((data) => {
        setAnalyses(data);
        if (data.length > 0) setSelectedId(data[0].id);
      })
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    apiFetch(`/analyses/${selectedId}`)
      .then(setDetail)
      .catch((err) => setError(err.message));
  }, [selectedId]);

  const sevOrder = ["CRITICAL", "SUSPICIOUS", "WARNING", "INFO"];
  const alerts = [...(detail?.alerts || [])].sort(
    (a, b) => sevOrder.indexOf(a.severite) - sevOrder.indexOf(b.severite)
  );

  return (
    <>
      <Header />
      <div style={{ padding: "28px 36px" }}>
        <div className="page-card">
          <h3>Alertes</h3>
          <p>Sélectionne une analyse pour afficher les alertes détectées.</p>
        </div>

        {error && <div className="no-alerts">{error}</div>}

        <div className="section-nav">
          {analyses.map((a) => (
            <button
              key={a.id}
              className={`nav-pill ${a.id === selectedId ? "active" : ""}`}
              onClick={() => setSelectedId(a.id)}
            >
              {a.filename}
            </button>
          ))}
        </div>

        {alerts.length === 0 ? (
          <div className="no-alerts">Aucune alerte à afficher.</div>
        ) : (
          alerts.map((alert, i) => (
            <div className="alert-card" key={i}>
              <div className="alert-head">
                <div>
                  <div className="alert-title">{alert.rule_id || "Alerte"}</div>
                  <div className="alert-sub">{alert.protocole || "—"} · {alert.cible || "—"}</div>
                </div>
                {sevBadge(alert.severite)}
              </div>
              <div className="description">{alert.description || "Aucune description fournie."}</div>
            </div>
          ))
        )}
      </div>
    </>
  );
}
