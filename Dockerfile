# Imagem apenas do servidor relay.
FROM python:3.13-slim
# - aplica as correções de segurança do Debian já publicadas (ex.: zlib)
# - instala a única dependência e depois remove pip/setuptools/wheel e as cópias
#   do ensurepip: não são usados em produção e trazem bibliotecas próprias
#   (urllib3, msgpack...) que só aumentam a superfície de ataque
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "cryptography>=42" \
 && { pip uninstall -y pip setuptools wheel || true; } \
 && rm -rf /usr/local/lib/python3*/ensurepip /usr/local/lib/python3*/site-packages/pip* \
           /usr/local/lib/python3*/site-packages/setuptools* /usr/local/lib/python3*/site-packages/wheel* \
           /usr/local/bin/pip* \
 && python -c "import cryptography" \
 && useradd -r -m crpto
COPY crptochat /app/crptochat
WORKDIR /app
USER crpto
VOLUME /data
EXPOSE 7777
ENTRYPOINT ["python", "-m", "crptochat.server", "--data", "/data"]
