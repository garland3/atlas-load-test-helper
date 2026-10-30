FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_MODULE=mock_oidc PORT=8000
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mock_oidc.py mock_litellm.py ./
RUN useradd --create-home appuser
USER appuser
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn ${APP_MODULE}:app --host 0.0.0.0 --port ${PORT}"]
