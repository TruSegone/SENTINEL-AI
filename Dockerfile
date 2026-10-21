FROM node:20-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 sentinel
COPY sentinel ./sentinel
COPY migrations ./migrations
COPY alembic.ini README.md ./
COPY --from=frontend-build /frontend/dist ./frontend/dist
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)" || exit 1
CMD ["sh", "-c", "alembic upgrade head && python -m sentinel.seed --count 500 && uvicorn sentinel.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
