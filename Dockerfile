FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Hugging Face Spaces serves the app on port 7860
EXPOSE 7860

CMD ["gunicorn", "src.main:app", "--bind", "0.0.0.0:7860", "--workers", "2", "--timeout", "120"]
