"""
main.py (enrichment-service)
Service d'enrichissement des données agrégées avant détection
(ex : géolocalisation IP, réputation, threat intel...).

⚠️ Je n'ai pas le contenu de ton dossier enrichment/, donc ce fichier est un
squelette. Remplace le TODO ci-dessous par l'appel à tes vraies fonctions
d'enrichissement (déplacées telles quelles dans le package enrichment/ local).

Endpoint :
    POST /enrich  -> reçoit les données agrégées, retourne les données enrichies

Lancer avec : uvicorn main:app --reload --port 8003
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Exemple, à adapter à tes vrais noms de fichiers/fonctions :
# from enrichment.enricher import enrich_data

app = FastAPI(
    title="Enrichment Service",
    description="Enrichissement des données réseau agrégées.",
    version="1.0.0",
)


class EnrichmentRequest(BaseModel):
    aggregated: dict


@app.post("/enrich", summary="Enrichit les données agrégées")
def enrich(payload: EnrichmentRequest) -> dict:
    try:
        # enriched = enrich_data(payload.aggregated)
        enriched = payload.aggregated  # TODO: brancher ta vraie logique d'enrichissement
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Erreur pendant l'enrichissement : {exc}") from exc
    return {"enriched": enriched}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}