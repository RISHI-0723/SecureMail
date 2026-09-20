# Backend Dockerfile for SecureMailScope
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies including TShark for packet analysis
# DEBIAN_FRONTEND=noninteractive prevents tshark installation prompts
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    gcc \
    postgresql-client \
    tshark \
    && rm -rf /var/lib/apt/lists/* \
    && tshark --version

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Run FastAPI with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
