# Stage unique basé sur l'image officielle Python
FROM python:3.11-slim           # Python 3.11 slim, image officielle Docker :contentReference[oaicite:4]{index=4}

# Variables pour un comportement optimal
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Installer whois et utilitaires DNS
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      whois \                      # pour la commande whois :contentReference[oaicite:5]{index=5} \
      dnsutils                     # utilitaires DNS :contentReference[oaicite:6]{index=6} \
 && rm -rf /var/lib/apt/lists/*   # nettoyer le cache apt :contentReference[oaicite:7]{index=7}

# Copier et installer les dépendances Python
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt  # pip sans cache :contentReference[oaicite:8]{index=8}

# Copier le code et exposer le port
COPY . .
EXPOSE 5000                                           # Port exposé :contentReference[oaicite:9]{index=9}

# Démarrer Flask en production
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
