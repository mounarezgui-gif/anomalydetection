import { useCallback, useEffect, useRef, useState } from "react";
import Header from "../components/Header";
import { apiFetch, uploadCapture } from "../api";
import { useToast } from "../components/Toast";

function sevBadge(sev) {
  return <span className={`sev-badge sev-${sev}`}>{sev}</span>;
}

function timeAgo(isoString) {
  const diff = (Date.now() - new Date(isoString).getTime()) / 1000;
  if (diff < 60) return "à l'instant";
  if (diff < 3600) return `il y a ${Math.floor(diff / 60)} min`;
  if (diff < 86400) return `il y a ${Math.floor(diff / 3600)} h`;
  return `il y a ${Math.floor(diff / 86400)} j`;
}

function formatDateTime(value) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return value;
  }
}

function formatDuration(value) {
  const seconds = Number(value || 0);
  return `${seconds.toFixed(seconds >= 10 ? 0 : 2)} s`;
}

function DetailsBlock({ details }) {
  if (!details || typeof details !== "object" || Array.isArray(details)) {
    return (
      <div className="detail-entry">
        <div className="detail-value">{String(details ?? "Aucun détail supplémentaire.")}</div>
      </div>
    );
  }
  return (
    <div className="detail-grid">
      {Object.entries(details).map(([key, value]) => (
        <div className="detail-entry" key={key}>
          <div className="detail-key">{key}</div>
          {Array.isArray(value) ? (
            <div className="chip-row">
              {value.map((item, i) => (
                <span className="chip" key={i}>{String(item)}</span>
              ))}
            </div>
          ) : value && typeof value === "object" ? (
            <pre className="detail-json">{JSON.stringify(value, null, 2)}</pre>
          ) : (
            <div className="detail-value">{String(value ?? "—")}</div>
          )}
        </div>
      ))}
    </div>
  );
}

export default function Console() {
  const [analyses, setAnalyses] = useState(null);
  const [listError, setListError] = useState(false);
  const [currentId, setCurrentId] = useState(null);
  const [currentData, setCurrentData] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [view, setView] = useState("overview");
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);
  const toast = useToast();

  const loadList = useCallback(async () => {
    try {
      const data = await apiFetch("/analyses");
      setAnalyses(data);
      setListError(false);
    } catch {
      setListError(true);
    }
  }, []);

  useEffect(() => {
    loadList();
  }, [loadList]);

  async function openAnalysis(id) {
    setCurrentId(id);
    setView("overview");
    setLoadingDetail(true);
    setDetailError("");
    try {
      const data = await apiFetch(`/analyses/${id}`);
      setCurrentData(data);
    } catch (err) {
      setDetailError(err.message);
    } finally {
      setLoadingDetail(false);
    }
  }

  async function handleDelete(id) {
    if (!confirm("Supprimer définitivement cette analyse ?")) return;
    try {
      await apiFetch(`/analyses/${id}`, { method: "DELETE" });
      toast("Analyse supprimée.");
      setCurrentId(null);
      setCurrentData(null);
      loadList();
    } catch (err) {
      toast(`Échec de la suppression : ${err.message}`, true);
    }
  }

  async function handleFile(file) {
    if (!file) return;
    const validExt = /\.(pcap|pcapng)$/i.test(file.name);
    if (!validExt) {
      toast("Extension non supportée. Utilise un .pcap ou .pcapng.", true);
      return;
    }
    toast(`Analyse de ${file.name} en cours...`);
    try {
      const body = await uploadCapture(file);
      toast(`${body.detection_summary.total_alerts} alerte(s) détectée(s) dans ${file.name}.`);
      await loadList();
      openAnalysis(body.id);
    } catch (err) {
      toast(`Échec de l'analyse : ${err.message}`, true);
    }
  }

  const cs = currentData?.capture_summary || {};
  const ds = currentData?.detection_summary || { total_alerts: 0 };
  const alerts = currentData?.alerts || [];
  const conversations = currentData?.conversations || [];
  const sevOrder = ["CRITICAL", "SUSPICIOUS", "WARNING", "INFO"];
  const sortedAlerts = [...alerts].sort(
    (a, b) => sevOrder.indexOf(a.severite) - sevOrder.indexOf(b.severite)
  );

  return (
    <>
      <Header />
      <div className="layout">
        <aside className="sidebar">
          <label
            className={`upload-zone ${dragOver ? "dragover" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={(e) => { e.preventDefault(); setDragOver(false); }}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              handleFile(e.dataTransfer.files[0]);
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => handleFile(e.target.files[0])}
            />
            <div className="upload-label"><strong>Déposer une capture</strong><br />ou cliquer pour parcourir</div>
            <div className="upload-hint">.pcap / .pcapng</div>
          </label>

          <div className="analysis-list">
            {analyses === null ? (
              <>
                <div className="list-eyebrow">Analyses</div>
                <div className="empty-state">{listError ? "Impossible de charger la liste. Vérifie que l'API tourne." : "Chargement..."}</div>
              </>
            ) : analyses.length === 0 ? (
              <>
                <div className="list-eyebrow">Analyses</div>
                <div className="empty-state">Aucune analyse pour l'instant.<br />Dépose une capture pour commencer.</div>
              </>
            ) : (
              <>
                <div className="list-eyebrow">Analyses ({analyses.length})</div>
                {analyses.map((a) => {
                  const sevEntries = Object.entries(a.detection_summary?.alerts_by_severity || {});
                  return (
                    <div
                      key={a.id}
                      className={`analysis-item ${a.id === currentId ? "active" : ""}`}
                      onClick={() => openAnalysis(a.id)}
                    >
                      <div className="filename">{a.filename}</div>
                      <div className="meta">
                        <span>{timeAgo(a.created_at)}</span>
                        <span>·</span>
                        <span>{a.total_packets} paquets</span>
                      </div>
                      {sevEntries.length > 0 && (
                        <div className="badge-row">
                          {sevEntries.map(([sev, count]) => (
                            <span key={sev}>{sevBadge(sev)} ×{count}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </aside>

        <main className="main">
          {!currentId ? (
            <div className="placeholder">
              <div className="radar"></div>
              <p>Sélectionne une analyse à gauche, ou dépose une capture pour commencer.</p>
            </div>
          ) : loadingDetail ? (
            <div className="placeholder"><div className="radar"></div><p>Chargement de l'analyse...</p></div>
          ) : detailError ? (
            <div className="placeholder"><p>Impossible de charger cette analyse ({detailError}).</p></div>
          ) : currentData ? (
            <>
              <div className="detail-header">
                <div>
                  <h2>{currentData.filename}</h2>
                  <div className="sub">{currentData.id} · {formatDateTime(currentData.created_at)}</div>
                </div>
                <button className="btn danger" onClick={() => handleDelete(currentData.id)}>Supprimer</button>
              </div>

              <div className="stat-grid">
                <div className="stat"><div className="value">{cs.total_packets ?? "—"}</div><div className="label">Paquets</div></div>
                <div className="stat"><div className="value">{cs.total_conversations ?? "—"}</div><div className="label">Conversations</div></div>
                <div className="stat"><div className="value">{ds.total_alerts}</div><div className="label">Alertes</div></div>
                <div className="stat"><div className="value">{formatDuration(cs.duration)}</div><div className="label">Durée capture</div></div>
              </div>

              <div className="section-nav">
                <button className={`nav-pill ${view === "overview" ? "active" : ""}`} onClick={() => setView("overview")}>Vue d'ensemble</button>
                <button className={`nav-pill ${view === "conversations" ? "active" : ""}`} onClick={() => setView("conversations")}>Conversations</button>
                <button className={`nav-pill ${view === "alerts" ? "active" : ""}`} onClick={() => setView("alerts")}>Alertes</button>
              </div>

              {view === "overview" && (
                <>
                  <div className="page-card">
                    <h3>Résumé de la capture</h3>
                    <p>Cette vue rapide met en avant les métriques clés et les alertes les plus sévères détectées durant l'analyse.</p>
                  </div>
                  <div className="section-title">Alertes détectées</div>
                  {sortedAlerts.length === 0 ? (
                    <div className="no-alerts">Aucune anomalie détectée sur cette capture.</div>
                  ) : (
                    sortedAlerts.map((a, i) => (
                      <div className="alert-row" key={i}>
                        <div>{sevBadge(a.severite)}</div>
                        <div className="protocole">{a.protocole || ""}</div>
                        <div><div className="description">{a.description}</div></div>
                        <div>
                          <div className="cible">{a.cible || "—"}</div>
                          <span className="timestamp">{formatDateTime(a.timestamp).split(",")[1] || formatDateTime(a.timestamp)}</span>
                        </div>
                      </div>
                    ))
                  )}
                </>
              )}

              {view === "conversations" && (
                <>
                  <div className="page-card">
                    <h3>Conversations observées</h3>
                    <p>Chaque conversation regroupe les paquets associés ainsi que les métadonnées principales de l'échange.</p>
                  </div>
                  {conversations.length === 0 ? (
                    <div className="no-alerts">Aucune conversation disponible dans cette analyse.</div>
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
                            <div className="metric-box"><div className="value">{formatDuration(conv.duration)}</div><div className="label">Durée</div></div>
                            <div className="metric-box"><div className="value">{(conv.ports || []).slice(0, 3).join(", ") || "—"}</div><div className="label">Ports</div></div>
                          </div>
                          <div className="packet-list">
                            {(conv.packets || []).length === 0 ? (
                              <div className="no-alerts">Aucun paquet détaillé pour cette conversation.</div>
                            ) : (
                              conv.packets.slice(0, 10).map((pkt, i) => (
                                <div className="packet-item" key={i}>
                                  <div className="packet-number">#{pkt.packet_number ?? "—"}</div>
                                  <div className="packet-main">
                                    <div className="route">{pkt.src_ip || "—"}:{pkt.src_port ?? "—"} → {pkt.dst_ip || "—"}:{pkt.dst_port ?? "—"}</div>
                                    <div className="meta">{pkt.protocol || "—"} · {pkt.timestamp_iso || pkt.timestamp || "—"}</div>
                                  </div>
                                  <div className="packet-side">
                                    {pkt.length_bytes ?? 0} B<br />
                                    {pkt.tcp ? (`${pkt.tcp.syn ? "SYN" : ""}${pkt.tcp.ack ? " ACK" : ""}${pkt.tcp.rst ? " RST" : ""}`.trim() || "—") : "—"}
                                  </div>
                                </div>
                              ))
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}

              {view === "alerts" && (
                <>
                  <div className="page-card">
                    <h3>Détails des alertes</h3>
                    <p>Chaque alerte expose sa règle, sa cible, sa gravité et les détails techniques associés.</p>
                  </div>
                  {sortedAlerts.length === 0 ? (
                    <div className="no-alerts">Aucune alerte disponible pour cette analyse.</div>
                  ) : (
                    sortedAlerts.map((alert, i) => (
                      <div className="alert-card" key={i}>
                        <div className="alert-head">
                          <div>
                            <div className="alert-title">{alert.rule_id || "Alerte"}</div>
                            <div className="alert-sub">{alert.protocole || "—"} · {alert.cible || "—"} · {formatDateTime(alert.timestamp)}</div>
                          </div>
                          {sevBadge(alert.severite)}
                        </div>
                        <div className="description">{alert.description || "Aucune description fournie."}</div>
                        <DetailsBlock details={alert.details} />
                      </div>
                    ))
                  )}
                </>
              )}
            </>
          ) : null}
        </main>
      </div>
    </>
  );
}
