# Stage 1: Build Astro Static Site
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Python Backend + Static files
# Match the local Python version to avoid behavioural differences between environments
FROM python:3.13-alpine
WORKDIR /app

# Install build dependencies for cryptography/bcrypt
RUN apk add --no-cache gcc musl-dev libffi-dev build-base

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Remove build deps to reduce attack surface and image size
RUN apk del gcc musl-dev libffi-dev build-base

# Copy application source
COPY src/api ./src/api
COPY --from=build /app/dist ./dist

# ── Security: run as non-root user ───────────────────────────────────────────
# If a vulnerability in a dependency is exploited, the attacker is limited to
# the appuser account and cannot write outside /app or escalate to root.
RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app

USER appuser

# Run uvicorn pointing to src.api.main:app
# Add --proxy-headers and TRUST_PROXY=1 in your compose file when behind nginx
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8100"]
