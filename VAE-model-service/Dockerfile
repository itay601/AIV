# Use a slim image to reduce size
FROM python:3.11-slim

# Set environment variables for cleaner installation
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .

RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt 

# Copy application code
COPY ./app /app

# Expose port
EXPOSE 5001

# Use uvicorn with faster reload (remove reload in production!)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5001"]