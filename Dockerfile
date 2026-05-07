FROM node:20-alpine AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci 2>/dev/null || npm install
COPY web/ .
RUN npm run build

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY core/ core/
COPY parsers/ parsers/
COPY api/ api/
COPY cli/ cli/
COPY report/ report/
COPY scripts/ scripts/

COPY --from=frontend /app/web/dist ./static

ENV STORAGE_PATH=/app/data/fw-insight.db
ENV MAX_RULES=5000

RUN mkdir -p /app/data

VOLUME /app/data

EXPOSE 8080

CMD ["fw-insight", "serve", "--host", "0.0.0.0", "--port", "8080"]
