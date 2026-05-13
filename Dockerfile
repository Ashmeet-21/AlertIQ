# AlertIQ Backend — FastAPI + psycopg3
# Uses Python 3.12 for Docker (Python 3.14 has no stable Docker image yet;
# the code is fully compatible with 3.12).
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY backend/ ./backend/

# Expose FastAPI port
EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
