"""
main.py (API)
Endpoints FastAPI :
    POST   /analyses            -> upload d'un .pcap/.pcapng, lance le pipeline complet, retourne le résumé
    GET    /analyses            -> liste toutes les analyses (résumé léger)
    GET    /analyses/{id}       -> détail complet d'une analyse (paquets + alertes)
    GET    /analyses/{id}/alerts -> uniquement les alertes d'une analyse
    DELETE /analyses/{id}       -> supprime une analyse

Lancer avec :  uvicorn app.api.main:app --reload
"""

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.analyzer import PacketExtractionError, aggregate_packets, extract_packets
from app.detector.engine import analyze
from dotenv import load_dotenv
load_dotenv()  # charge MONGODB_URI depuis le fichier .env
from . import storage
from .schemas import AnalysisDetail, AnalysisSummary, ErrorResponse
from .storage import StorageError
from app.auth.routes import router as auth_router

app = FastAPI(
    title="Network Anomaly Detector API",
    description="Analyse des captures PCAP et détection d'anomalies comportementales par protocole.",
    version="1.0.0",
)
app.include_router(auth_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # en production : liste précise des origines autorisées
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


def _to_summary(record: dict) -> AnalysisSummary:
    return AnalysisSummary(
        id=record["id"],
        filename=record["filename"],
        created_at=record["created_at"],
        total_packets=record["capture_summary"]["total_packets"],
        total_conversations=record["capture_summary"]["total_conversations"],
        detection_summary=record["detection_summary"],
    )


@app.post(
    "/analyses",
    response_model=AnalysisDetail,
    status_code=201,
    responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="Analyse un fichier PCAP et retourne les alertes détectées",
)
async def create_analysis(file: UploadFile = File(...)) -> AnalysisDetail:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Extension non supportée '{suffix}'. Attendu : {sorted(ALLOWED_EXTENSIONS)}",
        )

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Fichier vide.")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        packets = extract_packets(str(tmp_path))
        if not packets:
            raise HTTPException(status_code=422, detail="Aucun paquet exploitable dans ce fichier.")

        aggregated = aggregate_packets(packets)
        result = analyze(aggregated)

        analysis_id = storage.new_analysis_id()
        record = storage.save_analysis(analysis_id, file.filename, result)
        return record

    except PacketExtractionError as exc:
        raise HTTPException(status_code=422, detail=f"Erreur d'extraction TShark : {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)


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