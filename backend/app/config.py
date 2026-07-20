# config.py ou dans ton module principal
from dotenv import load_dotenv
import os

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VT_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY manquante dans .env")