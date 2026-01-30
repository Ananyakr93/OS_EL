# Build Stage
FROM ubuntu:22.04 AS builder

# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    libfuse3-dev \
    libssl-dev \
    libcmocka-dev \
    pkg-config \
    afl \
    attr \
    git \
    python3 \
    python3-pip \
    fio \
    bc \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Setup workspace
WORKDIR /app
COPY . .

# Build EncFS
RUN make clean && make

# Build Tests
RUN make test_crypto

# Install Python dependencies for Dashboard
RUN pip3 install -r dashboard/requirements.txt

# Expose dashboard port
EXPOSE 5000

# Default Command: Integration Test (needs privileged mode for FUSE)
# To run dashboard instead: python3 dashboard/app.py
CMD ["./tests/integration_test.sh"]

