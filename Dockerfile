# Use Python 3.12 slim image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create runtime directories (IMPORTANT)
RUN mkdir -p /app/quarantine \
    /app/backup \
    /app/honeypot \
    /app/data

# Give write permissions (CRITICAL for SQLite)
RUN chmod -R 777 /app

# Expose port
EXPOSE 5000

# Environment
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Start app
CMD ["python", "app.py"]