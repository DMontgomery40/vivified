# Minimal Dockerfile placeholder for example plugin
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN useradd -m -u 1001 vivified && chown -R vivified:vivified /app
USER vivified
CMD ["python", "-c", "print('Patient Record Manager example container')"]

