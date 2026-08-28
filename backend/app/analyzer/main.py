"""
main.py (analyzer-service)
Service d'extraction et d'agrégation des paquets réseau à partir d'un fichier PCAP.

Endpoint :
    POST /extract  -> reçoit un fichier .pcap/.pcapng, retourne les paquets agrégés (JSON)

Lancer avec : uvicorn main:app --reload --port 8001
"""

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from app.analyzer import PacketExtractionError, aggregate_packets, extract_packets

app = FastAPI(
    title="Analyzer Service",
    description="Extraction et agrégation de paquets à partir de fichiers PCAP.",
    version="1.0.0",
)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


@app.post("/extract", summary="Extrait et agrège les paquets d'un fichier PCAP")
async def extract_and_aggregate(file: UploadFile = File(...)) -> JSONResponse:
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
        # Si aggregate_packets renvoie un objet custom (dataclass/pydantic) plutôt
        # qu'un dict, adapte ici avec .dict() / .model_dump() / asdict() selon le cas.
        return JSONResponse(content={"packet_count": len(packets), "aggregated": aggregated})

    except PacketExtractionError as exc:
        raise HTTPException(status_code=422, detail=f"Erreur d'extraction TShark : {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}