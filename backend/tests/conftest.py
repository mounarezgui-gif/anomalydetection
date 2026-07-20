import mongomock
import pytest
from fastapi.testclient import TestClient

from app.api import storage
from app.api.main import app


@pytest.fixture()
def isolated_storage(monkeypatch):
    """Redirige storage.get_collection() vers une fausse base en mémoire (mongomock)
    pour chaque test -- aucun test ne touche jamais le vrai cluster Atlas."""
    fake_collection = mongomock.MongoClient()["test_db"]["analyses"]
    monkeypatch.setattr(storage, "get_collection", lambda: fake_collection)
    yield fake_collection


@pytest.fixture()
def client(isolated_storage):
    return TestClient(app)


@pytest.fixture()
def sample_pcap_path():
    from pathlib import Path
    return Path(__file__).parent / "fixtures" / "sample.pcap"