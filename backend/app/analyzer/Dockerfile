FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

# tshark nécessaire ici : c'est ce service qui extrait les paquets des fichiers PCAP
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    tshark \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./

EXPOSE 8001

CMD ["uvicorn", "app.analyzer.main:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]