FROM python:3.12-slim

# Системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем xray
ARG XRAY_VERSION=1.8.24
ARG TARGETARCH=amd64
RUN ARCH=${TARGETARCH} && \
    if [ "$ARCH" = "amd64" ]; then XARCH="64"; \
    elif [ "$ARCH" = "arm64" ]; then XARCH="arm64-v8a"; \
    else XARCH="64"; fi && \
    wget -q "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XARCH}.zip" \
         -O /tmp/xray.zip && \
    unzip -q /tmp/xray.zip -d /tmp/xray && \
    mv /tmp/xray/xray /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray /tmp/xray.zip

# Python-зависимости
RUN pip install --no-cache-dir aiohttp aiohttp-socks geoip2

# Создаем папку для GeoIP базы
RUN mkdir -p /usr/share/GeoIP

# Скачиваем базу GeoLite2-Country (с официального зеркала)
RUN wget -q https://git.io/GeoLite2-Country.mmdb -O /usr/share/GeoIP/GeoLite2-Country.mmdb


# Папка для результатов
RUN mkdir -p /data

WORKDIR /app
COPY runner.py .

# Переменные окружения (можно переопределить в docker run / compose)
ENV CONFIG_URL="https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"
ENV XRAY_BIN="xray"
ENV RUN_INTERVAL="3600"
ENV OUTPUT_DIR="/data"

# Монтируйте /data наружу, чтобы забирать tested_configs.txt
VOLUME ["/data"]

CMD ["python", "-u", "runner.py"]
