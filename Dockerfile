FROM python:3.14-slim

WORKDIR /app

RUN mkdir -p /data
ENV DB_PATH=/data/scans.db

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
