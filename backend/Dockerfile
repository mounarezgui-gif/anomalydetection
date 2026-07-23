FROM python:3.11-slim

# Empêche Python de bufferiser les logs (utile pour voir les logs en temps réel)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
# Dépendances système utiles (build, healthcheck, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    tshark \    
    && rm -rf /var/lib/apt/lists/*

# On copie d'abord requirements.txt pour profiter du cache Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du reste du code
COPY . .

EXPOSE 8000

# --reload uniquement en dev, à retirer en prod
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]