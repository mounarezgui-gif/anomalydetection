"""
test_api_analyses.py
Tests d'intégration des endpoints /analyses. Utilise TestClient (pas de
vrai serveur HTTP lancé), mais exécute le VRAI pipeline (tshark doit être
installé) sur un pcap de test réel.
"""

import io

import pytest


class TestListAnalyses:
    def test_empty_list_when_no_analysis(self, client):
        response = client.get("/analyses")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_contains_created_analysis(self, client, sample_pcap_path):
        with sample_pcap_path.open("rb") as f:
            client.post("/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")})

        response = client.get("/analyses")
        assert response.status_code == 200
        body = response.json()
        assert len(body) == 1
        assert body[0]["filename"] == "sample.pcap"

    def test_list_sorted_most_recent_first(self, client, sample_pcap_path):
        for _ in range(3):
            with sample_pcap_path.open("rb") as f:
                client.post("/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")})

        response = client.get("/analyses")
        timestamps = [item["created_at"] for item in response.json()]
        assert timestamps == sorted(timestamps, reverse=True)


class TestCreateAnalysis:
    def test_upload_valid_pcap_returns_201(self, client, sample_pcap_path):
        with sample_pcap_path.open("rb") as f:
            response = client.post(
                "/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        assert response.status_code == 201

    def test_upload_valid_pcap_returns_expected_shape(self, client, sample_pcap_path):
        with sample_pcap_path.open("rb") as f:
            response = client.post(
                "/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        body = response.json()
        assert "id" in body
        assert body["filename"] == "sample.pcap"
        assert "capture_summary" in body
        assert "conversations" in body
        assert "alerts" in body
        assert "detection_summary" in body
        assert body["capture_summary"]["total_packets"] > 0

    def test_upload_detects_expected_alert_rules(self, client, sample_pcap_path):
        """Le pcap de test contient du trafic sur ports non standards -> doit
        déclencher PROTOCOL_NON_STANDARD_PORT."""
        with sample_pcap_path.open("rb") as f:
            response = client.post(
                "/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        body = response.json()
        rule_names = {a["rule"] for a in body["alerts"]}
        assert "PROTOCOL_NON_STANDARD_PORT" in rule_names

    def test_upload_pcapng_extension_accepted(self, client, sample_pcap_path):
        with sample_pcap_path.open("rb") as f:
            content = f.read()
        response = client.post(
            "/analyses",
            files={"file": ("sample.pcapng", io.BytesIO(content), "application/octet-stream")},
        )
        # Le contenu n'est pas un vrai pcapng, donc tshark peut échouer (422) ou
        # réussir selon tolérance -- ce qu'on vérifie ici c'est que l'extension
        # elle-même n'est PAS rejetée avec un 400.
        assert response.status_code != 400

    def test_upload_rejects_wrong_extension(self, client):
        response = client.post(
            "/analyses", files={"file": ("notes.txt", b"hello world", "text/plain")}
        )
        assert response.status_code == 400
        assert "Extension" in response.json()["detail"]

    def test_upload_rejects_empty_file(self, client):
        response = client.post(
            "/analyses", files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 400

    def test_upload_rejects_corrupted_pcap(self, client):
        response = client.post(
            "/analyses",
            files={"file": ("corrupted.pcap", b"not a real pcap file content", "application/vnd.tcpdump.pcap")},
        )
        assert response.status_code == 422

    def test_upload_missing_file_returns_422(self, client):
        response = client.post("/analyses")
        assert response.status_code == 422  # erreur de validation FastAPI (champ requis manquant)


class TestGetAnalysisDetail:
    def test_get_existing_analysis_returns_200(self, client, sample_pcap_path):
        with sample_pcap_path.open("rb") as f:
            created = client.post(
                "/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
            ).json()

        response = client.get(f"/analyses/{created['id']}")
        assert response.status_code == 200
        assert response.json()["id"] == created["id"]

    def test_get_unknown_analysis_returns_404(self, client):
        response = client.get("/analyses/does-not-exist")
        assert response.status_code == 404
        assert "introuvable" in response.json()["detail"]


class TestGetAnalysisAlerts:
    def test_get_alerts_of_existing_analysis(self, client, sample_pcap_path):
        with sample_pcap_path.open("rb") as f:
            created = client.post(
                "/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
            ).json()

        response = client.get(f"/analyses/{created['id']}/alerts")
        assert response.status_code == 200
        body = response.json()
        assert "alerts" in body
        assert "detection_summary" in body
        assert body["detection_summary"]["total_alerts"] == len(body["alerts"])

    def test_get_alerts_of_unknown_analysis_returns_404(self, client):
        response = client.get("/analyses/does-not-exist/alerts")
        assert response.status_code == 404


class TestDeleteAnalysis:
    def test_delete_existing_analysis_returns_204(self, client, sample_pcap_path):
        with sample_pcap_path.open("rb") as f:
            created = client.post(
                "/analyses", files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
            ).json()

        response = client.delete(f"/analyses/{created['id']}")
        assert response.status_code == 204

        # doit être introuvable après suppression
        response = client.get(f"/analyses/{created['id']}")
        assert response.status_code == 404

    def test_delete_unknown_analysis_returns_404(self, client):
        response = client.delete("/analyses/does-not-exist")
        assert response.status_code == 404
