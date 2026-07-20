import json
import sys
from pathlib import Path

from app.analyzer import PacketExtractionError, aggregate_packets, extract_packets
from app.detector.engine import analyze

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ALERTS_DIR = PROJECT_ROOT / "alerts"
DEFAULT_OUTPUT_PATH = DEFAULT_ALERTS_DIR / "detection_result.json"


def _resolve_pcap_path(pcap_file: str) -> Path:
    """Resolve a PCAP path from the current directory, project root or samples/ folder."""
    candidate = Path(pcap_file)

    if candidate.is_absolute():
        if candidate.exists():
            return candidate
        raise FileNotFoundError(f"Fichier introuvable : {candidate}")

    cwd_candidate = (Path.cwd() / candidate).resolve()
    if cwd_candidate.exists():
        return cwd_candidate

    project_candidate = (PROJECT_ROOT / candidate).resolve()
    if project_candidate.exists():
        return project_candidate

    samples_candidate = (PROJECT_ROOT / "samples" / candidate).resolve()
    if samples_candidate.exists():
        return samples_candidate

    raise FileNotFoundError(f"Fichier introuvable : {pcap_file}")


def run(pcap_file: str, output_path: str | None = None) -> Path:
    pcap_path = _resolve_pcap_path(pcap_file)
    output = Path(output_path) if output_path else DEFAULT_OUTPUT_PATH
    output.parent.mkdir(parents=True, exist_ok=True)

    print("[1] Extraction PCAP")
    packets = extract_packets(str(pcap_path))
    print(f"{len(packets)} paquets extraits")

    print("[2] Agrégation")
    analysis = aggregate_packets(packets)

    print("[3] Détection")
    result = analyze(analysis)

    with output.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("Analyse terminée")
    print(f"Résultat : {output}")
    return output


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: python -m app.main fichier.pcap [fichier_json_sortie]")
        sys.exit(1)

    try:
        run(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}")
        sys.exit(1)
    except PacketExtractionError as exc:
        print(f"Erreur d'extraction TShark : {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"Erreur pendant l'exécution : {exc}")
        sys.exit(1)