from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Le service d'enrichissement peut fonctionner sans clé VirusTotal ; la clé est
# simplement optionnelle et doit être vérifiée au moment d'un appel réel.
# Cela évite un crash au chargement du module pendant les tests ou les exécutions
# locales sans variable d'environnement.
