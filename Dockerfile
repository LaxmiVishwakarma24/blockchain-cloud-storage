FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend backend
COPY frontend frontend
RUN useradd -m appuser && chown -R appuser /app
USER appuser
WORKDIR /app/backend
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "run:app"]