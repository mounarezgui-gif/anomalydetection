# Moteur d'analyse réseau - Extraction, agrégation et analyse fenêtrée par protocole

Ce livrable contient uniquement l'extraction, l'agrégation (globale ET
fenêtrée par protocole) et le suivi des handshakes TCP. Pas de moteur
de règles, pas de FastAPI, pas de base de données, pas de Docker.

## Structure

```
backend/
├── app/
│   ├── __init__.py
│   └── analyzer/
│       ├── __init__.py
│       ├── models.py          # Toutes les structures de données (voir plus bas)
│       ├── extractor.py        # Lecture PCAP/PCAPNG avec PyShark, normalisation UTC
│       ├── aggregator.py       # Agrégation globale ET fenêtrée par protocole
│       └── tcp_handshake.py    # Suivi d'état des handshakes TCP (SYN_SENT -> ESTABLISHED)
├── test.py                     # Script CLI de validation
├── requirements.txt
├── README.md
└── samples/
    ├── example_capture.pcap         # Scan de ports + rafale ICMP
    └── multi_protocol_test.pcap     # TCP complet/bloqué, DNS échoué, HTTP 404, ICMP
```

## Prérequis système

TShark doit être installé (PyShark s'appuie dessus) :

```bash
sudo apt install tshark          # Linux
# ou installer Wireshark sous Windows (inclut TShark), puis vérifier
# qu'il est bien dans le PATH système
```

## Installation

```bash
cd backend
python3 -m venv venv
source venv/bin/activate      # Windows : .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Utilisation

### Mode classique (agrégation sur tout le fichier)

```bash
python test.py samples/example_capture.pcap
python test.py samples/example_capture.pcap --top 10
```

### Nouveau mode : analyse par fenêtre temporelle, groupée par protocole

```bash
python test.py samples/multi_protocol_test.pcap --windowed
python test.py samples/example_capture.pcap --windowed --window-seconds 30 --handshake-timeout 5
```

Options disponibles :
- `--windowed` : active l'analyse par fenêtre (sinon uniquement le résumé global)
- `--window-seconds N` : durée de chaque fenêtre en secondes (défaut : 60)
- `--handshake-timeout N` : délai avant de marquer un handshake TCP comme incomplet (défaut : 5s)
- `--json-output chemin.json` : chemin du fichier JSON de sortie (défaut : `<capture>.windows.json`)

Ce mode découpe le fichier en fenêtres successives, regroupe les
paquets de chaque fenêtre par protocole (TCP, UDP, DNS, HTTP, ICMP) et
écrit un fichier JSON avec cette structure exacte :

```json
[
  {
    "window": {"start_time": "...", "end_time": "...", "duration": 60.0},
    "protocols": {
      "TCP": {"flows": [...], "features": {...}},
      "UDP": {"flows": [...], "features": {...}},
      "DNS": {"queries": [...], "features": {...}},
      "HTTP": {"requests": [...], "features": {...}},
      "ICMP": {"features": {...}}
    }
  }
]
```

## Détail des features calculées par protocole

| Protocole | Features | Détail |
|---|---|---|
| **TCP** | `packet_count`, `connection_count`, `syn_count`, `ack_count`, `rst_count`, `unique_dst_ports`, `incomplete_handshakes` | Chaque connexion (`flows`) a un état : `SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED` ou `RESET` |
| **UDP** | `packet_count`, `unique_dst_ports` | Flux groupés par `(src_ip, dst_ip, dst_port)` |
| **DNS** | `query_count`, `unique_domains`, `failed_queries`, `average_domain_length` | Une requête est "échouée" si sa réponse a un `rcode != 0` (ex. NXDOMAIN) |
| **HTTP** | `request_count`, `post_count`, `error_404`, `unique_urls` | Requêtes et réponses appariées par flux TCP |
| **ICMP** | `packet_count`, `echo_requests` | `echo_requests` = paquets de type 8 |

## Suivi des handshakes TCP (point 3 de la demande)

Chaque connexion TCP est identifiée par ses deux extrémités
`(ip, port)`, indépendamment du sens du paquet. L'état suit cette
logique :

1. **SYN_SENT** : premier paquet avec `SYN=1, ACK=0` observé (définit
   qui est l'initiateur/client)
2. **SYN_RECEIVED** : réponse `SYN=1, ACK=1` venant du répondeur
3. **ESTABLISHED** : `ACK=1, SYN=0` venant de l'initiateur
4. **RESET** : si un `RST=1` est observé à tout moment

Si une connexion reste en `SYN_SENT` au-delà du timeout configuré
(5s par défaut) avant la fin de la fenêtre, elle est marquée
`handshake_incomplete: true` et comptée dans
`TCP.features.incomplete_handshakes`.

**Limite documentée** : le suivi est local à chaque fenêtre. Une
connexion dont le SYN apparaît juste avant la fin d'une fenêtre peut
ne pas avoir eu le temps d'atteindre le timeout avant la limite de
fenêtre — elle reste alors `SYN_SENT` sans être marquée incomplète.
C'est un compromis volontaire pour garder l'analyse de chaque fenêtre
indépendante des autres.

## Normalisation UTC (point 1 de la demande)

`extractor.py` utilise `packet.sniff_timestamp` (l'epoch Unix brut,
indépendant du fuseau horaire) plutôt que `packet.sniff_time` (qui
dépend du fuseau système de la machine qui exécute l'analyse). Tous
les timestamps de `PacketRecord` sont donc des `datetime` UTC-aware
dès l'extraction, garantissant un fenêtrage cohérent quelle que soit
la machine sur laquelle tourne l'analyse.

## Vérifié réellement (pas juste écrit)

Ce code a été testé sur deux captures synthétiques générées avec
Scapy, couvrant : un handshake TCP complet, un handshake TCP bloqué
(jamais de réponse), une requête DNS en échec (NXDOMAIN), une réponse
HTTP 404, et un paquet ICMP echo request. Les 4 assertions suivantes
passent :

```python
protocols["TCP"]["features"]["incomplete_handshakes"] == 1
protocols["DNS"]["features"]["failed_queries"] == 1
protocols["HTTP"]["features"]["error_404"] == 1
protocols["ICMP"]["features"]["echo_requests"] == 1
```

## Utilisation programmatique

```python
from app.analyzer.extractor import PacketExtractor
from app.analyzer.aggregator import TrafficAggregator

extractor = PacketExtractor("capture.pcap")
packets = extractor.extract()

aggregator = TrafficAggregator(packets)

# Mode classique (tout le fichier)
result = aggregator.aggregate()

# Nouveau mode : par fenêtre de 60s, groupé par protocole
windows = aggregator.aggregate_by_window(window_seconds=60, handshake_timeout_seconds=5.0)
json_str = TrafficAggregator.windows_to_json(windows)
```

## Prochaine étape (hors périmètre de cette livraison)

Un moteur de règles pourra consommer directement `WindowResult`/le
JSON produit pour appliquer des règles spécifiques par protocole
(ex. : `incomplete_handshakes > seuil` pour un SYN flood, `failed_queries`
élevé pour du DNS tunneling, etc.), fenêtre par fenêtre plutôt que sur
tout le fichier d'un coup.
