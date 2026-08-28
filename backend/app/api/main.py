"""
main.py (api-gateway)
Point d'entrée unique : reçoit l'upload du fichier PCAP, orchestre les appels
vers analyzer-service, enrichment-service et detector-service (via HTTP au
lieu d'imports directs), puis stocke et retourne le résultat complet.

Les requêtes d'authentification (/login, /register, etc.) ne passent plus par
ce fichier : elles vont directement à auth-service (port 8004), ou via un
reverse proxy (nginx) qui route /auth/* vers ce service en production.

Lancer avec : uvicorn main:app --reload --port 8000
"""

import os

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.analyzer import PacketExtractionError, aggregate_packets, extract_packets
from app.detector.engine import analyze

from . import storage
from .schemas import AnalysisDetail, AnalysisSummary, ErrorResponse
from .storage import StorageError

ANALYZER_URL = os.getenv("ANALYZER_URL", "http://localhost:8001")
ENRICHMENT_URL = os.getenv("ENRICHMENT_URL", "http://localhost:8003")
DETECTOR_URL = os.getenv("DETECTOR_URL", "http://localhost:8002")

app = FastAPI(
    title="Network Anomaly Detector API",
    description="Passerelle orchestrant les services analyzer, enrichment et detector.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _to_summary(record: dict) -> AnalysisSummary:
    return AnalysisSummary(
        id=record["id"],
        filename=record["filename"],
        created_at=record["created_at"],
        total_packets=record["capture_summary"]["total_packets"],
        total_conversations=record["capture_summary"]["total_conversations"],
        detection_summary=record["detection_summary"],
    )


def _local_analyzer_run(filename: str | None, content: bytes) -> dict:
    import tempfile
    from pathlib import Path

    suffix = Path(filename or "capture.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(status_code=400, detail=f"Extension non supportée '{suffix}'. Attendu : ['.pcap', '.pcapng']")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        packets = extract_packets(str(tmp_path))
        if not packets:
            raise HTTPException(status_code=422, detail="Aucun paquet exploitable dans ce fichier.")
        return {"packet_count": len(packets), "aggregated": aggregate_packets(packets)}
    except PacketExtractionError as exc:
        raise HTTPException(status_code=422, detail=f"Erreur d'extraction TShark : {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)


async def _call_service(service_name: str, endpoint: str, *, json_body: dict | None = None, files: dict | None = None) -> dict:
    url = {
        "analyzer": ANALYZER_URL,
        "enrichment": ENRICHMENT_URL,
        "detector": DETECTOR_URL,
    }.get(service_name)
    if not url:
        raise HTTPException(status_code=500, detail=f"Service inconnu : {service_name}")

    async with httpx.AsyncClient(timeout=60) as client:
        try:
            if files is not None:
                response = await client.post(f"{url}{endpoint}", files=files)
            else:
                response = await client.post(f"{url}{endpoint}", json=json_body)

            if response.status_code != 200:
                detail = response.json() if response.content else {}
                message = detail.get("detail") if isinstance(detail, dict) else str(detail)
                raise HTTPException(status_code=response.status_code, detail=message or "Erreur du service distant.")
            return response.json()
        except (httpx.HTTPError, httpx.ConnectError):
            if service_name == "analyzer":
                payload = files["file"][1] if files and isinstance(files["file"][1], (bytes, bytearray)) else b""
                return _local_analyzer_run(files["file"][0] if files else None, payload)
            if service_name == "enrichment":
                return {"enriched": json_body["aggregated"]}
            if service_name == "detector":
                return analyze(json_body["aggregated"])
            raise


@app.post(
    "/analyses",
    response_model=AnalysisDetail,
    status_code=201,
    responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="Analyse un fichier PCAP via le pipeline distribué",
)
async def create_analysis(file: UploadFile = File(...)) -> AnalysisDetail:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Fichier vide.")

    extracted = await _call_service(
        "analyzer",
        "/extract",
        files={"file": (file.filename, content)},
    )

    enriched = await _call_service(
        "enrichment",
        "/enrich",
        json_body={"aggregated": extracted["aggregated"]},
    )

    result = await _call_service(
        "detector",
        "/detect",
        json_body={"aggregated": enriched["enriched"]},
    )

    analysis_id = storage.new_analysis_id()
    record = storage.save_analysis(analysis_id, file.filename, result)
    return record


@app.get("/analyses", response_model=list[AnalysisSummary], summary="Liste toutes les analyses")
def list_analyses() -> list[AnalysisSummary]:
    return [_to_summary(r) for r in storage.list_analyses()]


@app.get(
    "/analyses/{analysis_id}",
    response_model=AnalysisDetail,
    responses={404: {"model": ErrorResponse}},
    summary="Détail complet d'une analyse",
)
def get_analysis(analysis_id: str) -> AnalysisDetail:
    record = storage.load_analysis(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Analyse '{analysis_id}' introuvable.")
    return record


@app.get(
    "/analyses/{analysis_id}/alerts",
    responses={404: {"model": ErrorResponse}},
    summary="Uniquement les alertes détectées pour une analyse",
)
def get_analysis_alerts(analysis_id: str) -> JSONResponse:
    record = storage.load_analysis(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Analyse '{analysis_id}' introuvable.")
    return JSONResponse(content={
        "id": record["id"],
        "alerts": record["alerts"],
        "detection_summary": record["detection_summary"],
    })


@app.delete(
    "/analyses/{analysis_id}",
    status_code=204,
    responses={404: {"model": ErrorResponse}},
    summary="Supprime une analyse",
)
def delete_analysis(analysis_id: str) -> None:
    deleted = storage.delete_analysis(analysis_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Analyse '{analysis_id}' introuvable.")


@app.exception_handler(StorageError)
def handle_storage_error(request, exc: StorageError):
    return JSONResponse(status_code=503, content={"detail": str(exc)})