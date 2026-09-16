FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY app.py config.example.json README.md sample_jobs.json requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --shell /usr/sbin/nologin jobranker
RUN mkdir -p /data/imports /data/backups && chown -R jobranker:jobranker /app /data

USER jobranker
EXPOSE 8088

ENV APP_DATA_DIR=/data
CMD ["python", "/app/app.py", "--host", "0.0.0.0", "--port", "8088"]
