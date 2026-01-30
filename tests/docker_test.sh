#!/bin/bash
# ============================================================
# Docker-based Test Runner
# ============================================================
# Builds and runs the test suite inside Docker
# Usage: ./tests/docker_test.sh
# ============================================================

set -e

echo "=== Building Docker Image ==="
docker build -t encfs-test .

echo ""
echo "=== Running Unit Tests ==="
docker run --rm encfs-test ./test_crypto

echo ""
echo "=== Running Integration Tests ==="
echo "Note: FUSE requires --privileged mode"
docker run --rm --privileged --cap-add SYS_ADMIN --device /dev/fuse encfs-test ./tests/integration_test.sh

echo ""
echo "=== Running Full Test Suite ==="
docker run --rm --privileged --cap-add SYS_ADMIN --device /dev/fuse encfs-test ./tests/full_test_suite.sh

echo ""
echo "=== All Docker Tests Complete ==="
