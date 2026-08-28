"""
main.py (detector-service)
Service de détection d'anomalies à partir de données réseau déjà agrégées
(et éventuellement enrichies par enrichment-service).

Endpoint :
    POST /detect  -> reçoit les données agrégées en JSON, retourne le résultat de détection

Lancer avec : uvicorn main:app --reload --port 8002
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from engine import analyze

app = FastAPI(
    title="Detector Service",
    description="Détection d'anomalies comportementales à partir de conversations réseau agrégées.",
    version="1.0.0",
)


class DetectionRequest(BaseModel):
    aggregated: dict


@app.post("/detect", summary="Lance la détection sur des données agrégées")
def detect(payload: DetectionRequest) -> dict:
    try:
        result = analyze(payload.aggregated)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Erreur pendant la détection : {exc}") from exc
    return result


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}