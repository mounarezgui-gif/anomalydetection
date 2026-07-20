# backend/test.py
"""
Script de test manuel : extrait un PCAP, l'agrège, affiche un résumé
lisible en console, et écrit le résultat complet dans un fichier JSON.

Usage:
    python test.py [capture.pcap] [resultat.json]

Si non fournis :
    - capture.pcap est utilisé comme fichier PCAP par défaut
    - le JSON est écrit à côté, avec le même nom + suffixe ".analysis.json"
"""

import json
import os
import sys
from collections import Counter

# Ajouter le chemin du projet
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# L'API réelle exposée par le package : deux fonctions, pas de classes.
from app.analyzer import extract_packets, aggregate_packets, PacketExtractionError


def default_output_path(pcap_file: str) -> str:
    """Construit le chemin JSON de sortie par défaut à partir du PCAP."""
    base, _ext = os.path.splitext(pcap_file)
    return f"{base}.analysis.json"


def print_capture_summary(packets: list[dict], summary: dict) -> None:
    """Affiche les statistiques globales de la capture."""
    print("\n" + "=" * 60)
    print("=== STATISTIQUES GLOBALES ===")
    print("=" * 60)
    print(f"Total paquets         : {summary['total_packets']}")
    print(f"Total conversations   : {summary['total_conversations']}")
    print(f"Total octets          : {summary['total_bytes']:,}")
    print(f"Durée de la capture   : {summary['duration']}s")
    print(f"Début                 : {summary['start_time']}")
    print(f"Fin                   : {summary['end_time']}")

    # capture_summary.protocols n'est qu'une liste de noms ; on recalcule
    # le décompte par protocole ici, à partir des paquets extraits.
    protocol_counts = Counter(p["protocol"] for p in packets)
    print("\n📊 Distribution et décompte des protocoles :")
    for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        print(f"  - {proto:10}: {count:6} occurrences")


def print_conversations(conversations: list[dict], limit: int = 5) -> None:
    """Affiche les principales conversations (déjà triées par aggregate_packets)."""
    print("\n" + "=" * 60)
    print("=== ANALYSE DES CONVERSATIONS ===")
    print("=" * 60)
    print(f"🔍 Conversations détectées : {len(conversations)}")

    print(f"\n📋 Détail des {min(limit, len(conversations))} premières conversations :")
    for conv in conversations[:limit]:
        print(f"\n  [Conversation #{conv['conversation_id']}] "
              f"{conv['ip_a']} <-> {conv['ip_b']}")
        print(f"   | Paquets     : {conv['total_packets']}")
        print(f"   | Octets      : {conv['total_bytes']:,}")
        print(f"   | Protocoles  : {', '.join(conv['protocols_used'])}")
        print(f"   | Ports       : {conv['ports']}")
        print(f"   | Durée       : {conv['duration']}s "
              f"({conv['start_time']} -> {conv['end_time']})")

        # Un tcp.stream ne correspond pas à la conversation, mais on peut
        # lister les handshakes distincts observés à l'intérieur de celle-ci.
        seen_streams: set[int] = set()
        for packet in conv["packets"]:
            tcp = packet.get("tcp")
            if not tcp or tcp["stream"] in seen_streams:
                continue
            seen_streams.add(tcp["stream"])

            handshake = tcp["handshake"]
            status = "✅ COMPLET" if handshake["completed"] else "❌ INCOMPLET"
            if tcp["rst"]:
                status += " (⚠️ RESET observé sur ce paquet)"
            elif tcp["fin"]:
                status += " (FIN observé sur ce paquet)"

            print(f"     - tcp.stream {tcp['stream']}: "
                  f"SYN={handshake['syn_seen']} "
                  f"SYN-ACK={handshake['syn_ack_seen']} "
                  f"ACK={handshake['ack_seen']} -> {status}")





def main() -> None:
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
    output_json = sys.argv[2] if len(sys.argv) > 2 else default_output_path(pcap_file)

    print("=" * 60)
    print("=== TEST D'EXTRACTION ET D'AGRÉGATION PCAP ===")
    print("=" * 60)
    print(f"📁 Fichier source : {pcap_file}")
    print(f"📄 Fichier JSON   : {output_json}")

    if not os.path.exists(pcap_file):
        print(f"❌ Fichier '{pcap_file}' non trouvé !")
        print(f"   Répertoire courant : {os.getcwd()}")
        return

    try:
        # 1. Extraction (une seule passe TShark)
        print("\n📡 Extraction des paquets (extract_packets)...")
        packets = extract_packets(pcap_file)

        print(f"✅ {len(packets)} paquets extraits avec succès.")
        if not packets:
            print("⚠ Aucun paquet exploitable trouvé.")
            return

        # 2. Agrégation en conversations + calcul des handshakes
        print("\n📊 Agrégation des paquets (aggregate_packets)...")
        result = aggregate_packets(packets)

        # 3. Affichage console
        print_capture_summary(packets, result["capture_summary"])
        print_conversations(result["conversations"])

       
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print("\n" + "=" * 60)
        print(f"✅ PCAP ANALYSÉ AVEC SUCCÈS ! Résultat écrit dans : {output_json}")
        print("=" * 60)

    except PacketExtractionError as e:
        print(f"\n❌ Erreur d'extraction TShark : {e}")
    except Exception as e:
        print(f"\n❌ Erreur pendant l'exécution : {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()