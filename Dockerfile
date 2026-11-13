FROM python:3.12-slim

# liboqs (the post-quantum C library) is compiled from source by liboqs-python on first import.
# Doing that here means it happens once, at image build time, not on every machine / every run.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first so this (slow) layer is cached until requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Trigger the liboqs build now (the 30+ minute step from the README, but only once).
RUN python -c "import oqs; print('liboqs', oqs.oqs_version())"

COPY . .

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
