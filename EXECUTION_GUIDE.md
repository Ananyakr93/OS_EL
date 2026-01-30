# EncFS Project - Complete Execution Guide

> **Last Updated**: January 2026  
> **Target Platform**: Linux (Docker recommended) | Windows (WSL2)

This guide walks you through executing this encrypted filesystem project from scratch, including setup, building, testing, and running performance benchmarks.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Project Structure Overview](#2-project-structure-overview)
3. [Method 1: Docker Execution (Recommended)](#3-method-1-docker-execution-recommended)
4. [Method 2: Native Linux Execution](#4-method-2-native-linux-execution)
5. [Method 3: Windows WSL2 Execution](#5-method-3-windows-wsl2-execution)
6. [Running the Encrypted Filesystem](#6-running-the-encrypted-filesystem)
7. [Testing the Project](#7-testing-the-project)
8. [Performance Benchmarks](#8-performance-benchmarks)
9. [Dashboard (Web Interface)](#9-dashboard-web-interface)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|:----------|:--------|:------------|
| OS | Linux kernel 4.0+ | Ubuntu 22.04 LTS |
| RAM | 2 GB | 4 GB |
| Storage | 1 GB free | 5 GB (for benchmarks) |
| Docker | 20.10+ | 24.0+ |

### Software Dependencies

**For Docker Method:**
- Docker Desktop or Docker Engine
- Git

**For Native Linux:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libfuse3-dev \
    libssl-dev \
    libcmocka-dev \
    pkg-config \
    attr \
    fio \
    python3 \
    python3-pip

# Verify FUSE 3 installation
pkg-config --modversion fuse3  # Should show 3.x.x
```

---

## 2. Project Structure Overview

```
OS_EL/
├── src/
│   ├── encfs.c           # Main FUSE filesystem implementation
│   ├── logger.c          # Performance logging
│   └── fs/               # Filesystem helpers
│       ├── path.c        # Path resolution
│       ├── block_meta.c  # Metadata management
│       └── zk_proof.c    # Zero-Knowledge proof generation
├── crypto/
│   ├── aes.c             # AES-256 encryption (GCM/CTR)
│   └── hash.c            # SHA-256, HMAC, PBKDF2
├── include/              # Header files
├── tests/
│   ├── integration_test.sh
│   ├── full_test_suite.sh
│   ├── performance_benchmark.sh
│   ├── generate_perf_graphs.py
│   └── test_crypto.c
├── dashboard/            # Flask web interface
│   ├── app.py
│   └── templates/
├── Dockerfile
├── Makefile
├── README.md
└── REPORT.md             # Detailed technical report
```

---

## 3. Method 1: Docker Execution (Recommended)

This is the **easiest and most reliable** method as it handles all dependencies automatically.

### Step 3.1: Clone the Repository

```bash
# If you received the project as a zip, extract it first
# Otherwise, clone from git:
git clone <repository-url> OS_EL
cd OS_EL
```

### Step 3.2: Build the Docker Image

```bash
docker build -t encfs-project .
```

**Expected Output:**
```
Step 1/10 : FROM ubuntu:22.04 AS builder
 ---> ...
Step 10/10 : CMD ["./tests/integration_test.sh"]
 ---> ...
Successfully built <image-id>
Successfully tagged encfs-project:latest
```

### Step 3.3: Run Integration Tests

```bash
# Run the default integration test
docker run --privileged encfs-project
```

**Important**: The `--privileged` flag is **required** for FUSE operations.

### Step 3.4: Interactive Mode (Full Access)

```bash
# Start an interactive shell inside the container
docker run --privileged -it encfs-project /bin/bash

# Now you're inside the container:
root@container:/app# make clean && make
root@container:/app# ./tests/full_test_suite.sh
```

### Step 3.5: Run with Volume Mount (Persist Data)

```bash
# Create directories on host
mkdir -p ./output_results

# Run with volume mount
docker run --privileged -v $(pwd)/output_results:/app/benchmark_results \
    encfs-project /bin/bash -c \
    "make clean && make && ./tests/performance_benchmark.sh"
```

---

## 4. Method 2: Native Linux Execution

### Step 4.1: Install Dependencies

```bash
# Update package list
sudo apt-get update

# Install build dependencies
sudo apt-get install -y \
    build-essential \
    libfuse3-dev \
    libssl-dev \
    libcmocka-dev \
    pkg-config \
    attr \
    fio \
    bc \
    jq \
    python3 \
    python3-pip

# Install Python dependencies for graphs
pip3 install matplotlib numpy flask
```

### Step 4.2: Verify FUSE is Available

```bash
# Check FUSE version
pkg-config --modversion fuse3

# Check kernel module
lsmod | grep fuse

# If fuse module is not loaded:
sudo modprobe fuse
```

### Step 4.3: Build the Project

```bash
cd OS_EL

# Clean and build
make clean
make

# Expected output:
# gcc ... -c src/encfs.c -o src/encfs.o
# gcc ... -o encfs
# Build complete: encfs
```

### Step 4.4: Verify Build

```bash
# Check the binary was created
ls -la encfs
# -rwxr-xr-x 1 user user 58168 ... encfs

# Check it's executable
./encfs --help
```

---

## 5. Method 3: Windows WSL2 Execution

### Step 5.1: Enable WSL2

```powershell
# Run in PowerShell as Administrator
wsl --install -d Ubuntu-22.04
```

### Step 5.2: Configure WSL2 for FUSE

```bash
# Inside WSL2 Ubuntu terminal:

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential libfuse3-dev libssl-dev \
    libcmocka-dev pkg-config attr fuse3

# Enable user_allow_other in FUSE config
echo "user_allow_other" | sudo tee -a /etc/fuse.conf
```

### Step 5.3: Navigate to Project

```bash
# Windows paths are mounted at /mnt/
cd /mnt/d/OS_EL

# Build
make clean && make
```

**⚠️ Note**: FUSE in WSL2 has some limitations. Docker method is more reliable.

---

## 6. Running the Encrypted Filesystem

### Step 6.1: Create Required Directories

```bash
cd OS_EL

# Create cipher directory (stores encrypted files)
mkdir -p cipher

# Create mount point (where you access decrypted files)
mkdir -p mnt
```

### Step 6.2: Mount the Filesystem

```bash
# Mount in SECURE mode (AES-256-GCM with integrity)
./encfs cipher mnt -o passphrase=your_secret_password,mode=secure

# Or mount in SPEED mode (AES-256-CTR, faster)
./encfs cipher mnt -o passphrase=your_secret_password,mode=speed
```

### Step 6.3: Verify Mount

```bash
# Check if mounted
mount | grep encfs
# OR
cat /proc/mounts | grep mnt

# Should show something like:
# encfs on /path/to/mnt type fuse.encfs (rw,nosuid,nodev,user=...)
```

### Step 6.4: Use the Filesystem

```bash
# Write a file (transparently encrypted)
echo "This is secret data!" > mnt/secret.txt

# Read the file (transparently decrypted)
cat mnt/secret.txt

# Check the cipher directory (encrypted content)
cat cipher/secret.txt  # You'll see garbage/encrypted data
xxd cipher/secret.txt | head  # Binary view

# Check metadata file
cat cipher/secret.txt.meta
```

### Step 6.5: Advanced Features

```bash
# Set encryption policy via extended attributes
setfattr -n user.enc_policy -v "Speed" mnt/myfile.txt

# Set HEAD encryption (first N blocks only)
setfattr -n user.enc_policy -v "HEAD:100" mnt/largefile.bin

# Get Zero-Knowledge proof
getfattr -n user.zk_proof mnt/secret.txt
# Output: user.zk_proof="ZK-MOCK-PROOF:..."
```

### Step 6.6: Unmount the Filesystem

```bash
# Proper unmount
fusermount -u mnt

# If busy, force unmount
fusermount -uz mnt  # Lazy unmount
```

---

## 7. Testing the Project

### 7.1: Unit Tests (Cryptographic Functions)

```bash
# Build and run unit tests
make test

# Expected output:
# === Running Unit Tests ===
# [==========] Running 3 test(s).
# [ RUN      ] test_aes_gcm_roundtrip
# [       OK ] test_aes_gcm_roundtrip
# ...
# [==========] 3 test(s) run.
# [  PASSED  ] 3 test(s).
```

### 7.2: Integration Tests

```bash
# Run basic integration tests
# Requires sudo for FUSE operations
sudo ./tests/integration_test.sh

# Or use make target
sudo make integration-test
```

### 7.3: Full Test Suite (Comprehensive)

```bash
# Run all 12 test scenarios
sudo ./tests/full_test_suite.sh

# Expected output:
# ========================================
# EncFS Full Test Suite - <timestamp>
# ========================================
# [INFO] Building project...
# [INFO] Starting test suite...
# [INFO] TEST 1: Basic Mount/Unmount
# [PASS] Mount successful
# [PASS] Unmount successful
# ...
# ========================================
# TEST SUMMARY
# ========================================
# PASSED: 12
# FAILED: 0
# SKIPPED: 0
# ========================================
```

### 7.4: Test Scenarios Covered

| Test ID | Scenario | What It Verifies |
|:--------|:---------|:-----------------|
| T1 | Basic Mount/Unmount | FUSE mount appears in /proc/mounts |
| T2 | Partial + Full Blocks | < 4KB, exact 4KB, mixed sizes work |
| T3 | Encryption Verification | Ciphertext ≠ Plaintext |
| T4 | Policy via xattr | HEAD:N policy applies |
| T5 | Beyond HEAD Range | Blocks past HEAD:N use speed mode |
| T6 | Crash Recovery | Metadata HMAC survives crash |
| T7 | Concurrent Access | flock prevents corruption |
| T8 | Clean Unmount | No stale lock files |
| T9 | Wrong Passphrase | Decryption fails gracefully |
| T10 | Large File (1GB) | Performance logging works |
| T11 | ZK Proof | getfattr returns mock proof |
| T12 | Superblock Optimization | 32KB batched writes work |

---

## 8. Performance Benchmarks

### 8.1: Run Comprehensive Benchmarks

```bash
# Run the performance benchmark script
# This compares Secure vs Speed vs Plain ext4 vs eCryptfs
sudo ./tests/performance_benchmark.sh

# For smaller test (128MB instead of 1GB):
sudo ./tests/performance_benchmark.sh 128
```

### 8.2: Generate Performance Graphs

```bash
# Install Python dependencies (if not already)
pip3 install matplotlib numpy

# Generate graphs
python3 tests/generate_perf_graphs.py

# Output:
# ============================================================
# EncFS Performance Graph Generator
# ============================================================
# Generating graphs...
# Saved: benchmark_results/graphs/throughput_comparison.png
# Saved: benchmark_results/graphs/latency_comparison.png
# Saved: benchmark_results/graphs/cpu_overhead.png
# Saved: benchmark_results/graphs/summary_table.png
```

### 8.3: View Results

```bash
# CSV results
cat benchmark_results/performance_results.csv

# Graphs are in:
ls benchmark_results/graphs/
# cpu_overhead.png
# latency_comparison.png
# summary_table.png
# throughput_comparison.png
```

### 8.4: Quick Manual Benchmark

```bash
# Mount in speed mode
./encfs cipher mnt -o passphrase=test123,mode=speed &
sleep 2

# Write 1GB
dd if=/dev/zero of=mnt/testfile.bin bs=1M count=1024 conv=fdatasync

# Read 1GB
dd if=mnt/testfile.bin of=/dev/null bs=1M

# Unmount
fusermount -u mnt
```

---

## 9. Dashboard (Web Interface)

### 9.1: Install Dashboard Dependencies

```bash
cd dashboard
pip3 install -r requirements.txt
```

### 9.2: Start the Dashboard

```bash
# From the dashboard directory
python3 app.py

# Or from project root
python3 dashboard/app.py

# Expected output:
# * Running on http://127.0.0.1:5000
```

### 9.3: Access Dashboard

Open browser and navigate to: **http://localhost:5000**

Features:
- Mount/Unmount filesystem
- View file listings
- Monitor performance metrics
- Change encryption policies

### 9.4: Run Dashboard Tests

```bash
./tests/test_dashboard.sh
```

---

## 10. Troubleshooting

### Common Issues and Solutions

#### Issue 1: "fuse: device not found"
```bash
# Solution: Load FUSE kernel module
sudo modprobe fuse

# Make permanent (Ubuntu)
echo "fuse" | sudo tee -a /etc/modules
```

#### Issue 2: "Permission denied" on mount
```bash
# Solution: Run with sudo or configure fuse.conf
echo "user_allow_other" | sudo tee -a /etc/fuse.conf

# Or run with sudo
sudo ./encfs cipher mnt -o passphrase=test,mode=secure
```

#### Issue 3: "Transport endpoint is not connected"
```bash
# Solution: Force unmount and retry
fusermount -uz mnt
rm -rf mnt && mkdir mnt
```

#### Issue 4: Build fails with "fuse3 not found"
```bash
# Solution: Install FUSE 3 development libraries
sudo apt-get install libfuse3-dev

# Verify installation
pkg-config --cflags --libs fuse3
```

#### Issue 5: "setfattr: command not found"
```bash
# Solution: Install attr package
sudo apt-get install attr
```

#### Issue 6: Docker "operation not permitted"
```bash
# Solution: Use --privileged flag
docker run --privileged -it encfs-project /bin/bash
```

#### Issue 7: Graphs not generating (matplotlib error)
```bash
# Solution: Use non-GUI backend
export MPLBACKEND=Agg
python3 tests/generate_perf_graphs.py
```

---

## Quick Reference Commands

```bash
# Build
make clean && make

# Mount (Secure mode)
./encfs cipher mnt -o passphrase=YOUR_PASSWORD,mode=secure

# Mount (Speed mode)
./encfs cipher mnt -o passphrase=YOUR_PASSWORD,mode=speed

# Unmount
fusermount -u mnt

# Run all tests
sudo ./tests/full_test_suite.sh

# Run benchmarks
sudo ./tests/performance_benchmark.sh

# Generate graphs
python3 tests/generate_perf_graphs.py

# Start dashboard
python3 dashboard/app.py

# Docker quick test
docker run --privileged encfs-project
```

---

## Summary Checklist

- [ ] Prerequisites installed (FUSE3, OpenSSL, CMocka)
- [ ] Project built successfully (`make`)
- [ ] Unit tests pass (`make test`)
- [ ] Integration tests pass (`sudo ./tests/integration_test.sh`)
- [ ] Full test suite passes (`sudo ./tests/full_test_suite.sh`)
- [ ] Can mount/unmount filesystem
- [ ] Can read/write encrypted files
- [ ] Performance benchmarks completed
- [ ] Graphs generated
- [ ] Dashboard accessible (optional)

---

**For questions or issues, refer to:**
- `README.md` - Project overview
- `REPORT.md` - Technical details and performance evaluation
- `tests/` - Test scripts and expected outputs
