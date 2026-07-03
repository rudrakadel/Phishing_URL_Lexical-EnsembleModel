FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcursor1 \
    libxi6 \
    libxext6 \
    libxrender1 \
    libglib2.0-0 \
    libdbus-1-3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY flask_phishing_app/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
RUN playwright install chromium

COPY flask_phishing_app /app
COPY Model /models/Model

ENV PHISHING_MODEL_DIR=/models \
    APP_ENV=production \
    FLASK_DEBUG=0

EXPOSE 5000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
