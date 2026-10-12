FROM node:22-bookworm-slim AS frontend-build

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PDFSHIELD_USE_MANAGED_DB=false

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

COPY --from=frontend-build /app/frontend/dist/ ./frontend/dist/

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-3000}"]


EXPOSE 3000

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-3000}"]
