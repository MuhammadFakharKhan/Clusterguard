FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 HOST=0.0.0.0
WORKDIR /app
RUN useradd --uid 10001 --create-home appuser
COPY . /app
RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 8080
CMD ["python", "-m", "clusterguard.server"]
