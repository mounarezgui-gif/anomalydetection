"""
storage.py
Persistance des analyses dans MongoDB Atlas (au lieu de fichiers JSON).

Interface publique STRICTEMENT identique à la version fichiers :
    new_analysis_id(), save_analysis(), load_analysis(), list_analyses(),
    delete_analysis()
-> app/api/main.py n'a besoin d'aucune autre modification que le chargement
   du .env (voir plus bas).

Connexion paresseuse : le client Mongo n'est créé qu'au premier appel
(via get_collection()), pas à l'import du module. Ça permet de faire tourner
les tests avec une fausse collection (mongomock) sans jamais toucher au
vrai cluster Atlas, en monkeypatchant get_collection().
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError


DATABASE_NAME = os.environ.get("MONGODB_DB_NAME", "network_anomaly_detector")
COLLECTION_NAME = "analyses"

_client: Optional[MongoClient] = None


class StorageError(Exception):
    """Erreur de connexion ou d'opération sur la base de données."""


def get_collection() -> Collection:
    global _client
    if _client is None:
        mongodb_uri = os.environ.get("MONGODB_URI_ANALYSES")
        if not mongodb_uri:
            raise StorageError(...)
        _client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
    return _client[DATABASE_NAME][COLLECTION_NAME]

def new_analysis_id() -> str:
    return str(uuid.uuid4())


def save_analysis(analysis_id: str, filename: str, result: dict) -> dict:
    """Enrichit le résultat avec les métadonnées (id, filename, date) et l'insère en base."""
    record = {
        "id": analysis_id,
        "filename": filename,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    try:
        get_collection().insert_one({**record, "_id": analysis_id})
    except PyMongoError as exc:
        raise StorageError(f"Échec de l'enregistrement en base : {exc}") from exc
    return record


def load_analysis(analysis_id: str) -> dict | None:
    try:
        return get_collection().find_one({"_id": analysis_id}, {"_id": 0})
    except PyMongoError as exc:
        raise StorageError(f"Échec de la lecture en base : {exc}") from exc


def list_analyses() -> list[dict]:
    """Retourne toutes les analyses, triées de la plus récente à la plus ancienne."""
    try:
        cursor = get_collection().find({}, {"_id": 0}).sort("created_at", -1)
        return list(cursor)
    except PyMongoError as exc:
        raise StorageError(f"Échec de la lecture en base : {exc}") from exc


def delete_analysis(analysis_id: str) -> bool:
    try:
        result = get_collection().delete_one({"_id": analysis_id})
    except PyMongoError as exc:
        raise StorageError(f"Échec de la suppression en base : {exc}") from exc
    return result.deleted_count > 0