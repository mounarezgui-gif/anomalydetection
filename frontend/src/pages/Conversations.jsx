import { useEffect, useState } from "react";
import Header from "../components/Header";
import { apiFetch } from "../api";

export default function Conversations() {
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

  const conversations = detail?.conversations || [];

  return (
    <>
      <Header />
      <div style={{ padding: "28px 36px" }}>
        <div className="page-card">
          <h3>Conversations</h3>
          <p>Sélectionne une analyse pour afficher les conversations détectées.</p>
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

        {conversations.length === 0 ? (
          <div className="no-alerts">Aucune conversation à afficher.</div>
        ) : (
          <div className="conversation-grid">
            {conversations.map((conv) => (
              <div className="conversation-card" key={conv.conversation_id}>
                <div className="card-top">
                  <div>
                    <div className="card-title">Conversation #{conv.conversation_id ?? "—"}</div>
                    <div className="card-sub">{conv.ip_a || "—"} ↔ {conv.ip_b || "—"}</div>
                  </div>
                  <div className="chip-row">
                    {(conv.protocols_used || []).length > 0
                      ? conv.protocols_used.map((p, i) => <span className="chip" key={i}>{p}</span>)
                      : <span className="chip">Inconnu</span>}
                  </div>
                </div>
                <div className="metric-grid">
                  <div className="metric-box"><div className="value">{conv.total_packets ?? 0}</div><div className="label">Paquets</div></div>
                  <div className="metric-box"><div className="value">{conv.total_bytes ?? 0} B</div><div className="label">Taille</div></div>
                  <div className="metric-box"><div className="value">{(conv.duration ?? 0).toFixed?.(2) ?? conv.duration} s</div><div className="label">Durée</div></div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
