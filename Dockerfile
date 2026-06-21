# Stage 1: Build Astro Static Site
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Python Backend + Static files
FROM python:3.11-alpine
WORKDIR /app

# Install build dependencies for cryptography/bcrypt
RUN apk add --no-cache gcc musl-dev libffi-dev build-base

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Remove build deps to save space
RUN apk del gcc musl-dev libffi-dev build-base

# Copy python backend code
COPY src/api ./src/api

# Copy static frontend files from Node stage
COPY --from=build /app/dist ./dist

# Run uvicorn pointing to src.api.main:app
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
