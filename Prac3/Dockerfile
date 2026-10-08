FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py index.html style.css app.js ./

RUN adduser -D -u 10001 appuser
USER appuser

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000 8443

CMD ["python", "server.py"]
