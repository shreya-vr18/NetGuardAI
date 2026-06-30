FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY dashboard/ dashboard/
COPY models/ models/
COPY data/ data/

WORKDIR /app/backend

EXPOSE 5000

CMD ["python", "server.py"]