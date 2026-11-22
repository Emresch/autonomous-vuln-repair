FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Pytest ve benchmark bağımlılıkları (hem amd64 hem arm64 uyumlu)
RUN pip install --no-cache-dir pytest pyyaml defusedxml

# Konteyner varsayılan komutu
CMD ["pytest", "-o", "cache_dir=/tmp/pytest_cache"]
