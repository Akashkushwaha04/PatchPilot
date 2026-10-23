# ==============================================================================
# PatchPilot AI - Multi-Stage Production Dockerfile
# ==============================================================================

# --- Stage 1: Build the React Frontend ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

# --- Stage 2: Python Production Runtime ---
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    PATCHPILOT_DB=/app/data/patchpilot.db

WORKDIR /app

# Install system dependencies needed for Playwright and scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Install Playwright browser dependencies (Chromium only for lightweight footprint)
RUN playwright install --with-deps chromium || true

# Copy backend source
COPY backend/ ./backend/
COPY demo/ ./demo/
COPY PatchPilot_Executive_Summary_and_Roadmap.pdf ./

# Copy compiled frontend from Stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Ensure data directory exists
RUN mkdir -p /app/data

# Security compliance: create and switch to non-root app user (Rule PP-IAC-001)
RUN groupadd -g 10001 patchpilot && \
    useradd -u 10001 -g patchpilot -m -s /bin/bash appuser && \
    chown -R appuser:patchpilot /app

USER appuser

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/api/health || exit 1

# Launch production server respecting dynamic cloud PORT environment variable
CMD ["sh", "-c", "cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
