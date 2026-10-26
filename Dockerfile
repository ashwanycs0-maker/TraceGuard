# Stage 1: Base image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies if required for PDF rendering & networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-privileged user for security
RUN groupadd -r traceguard && useradd -r -g traceguard -d /app -s /sbin/nologin traceguard

# Copy application source code
COPY backend/ ./backend/
COPY static/ ./static/
COPY run.py .

# Create cases storage directory and set ownership to traceguard user
RUN mkdir -p /app/cases_storage/evidence_files && \
    chown -R traceguard:traceguard /app

# Switch to non-root user
USER traceguard

# Expose FastAPI service port
EXPOSE 8000

# Health check to ensure API is responding
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/cases || exit 1

# Start Uvicorn ASGI server
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
