CC = gcc
CFLAGS = -Wall -Wextra -g `pkg-config fuse3 --cflags` -I./include
LDFLAGS = `pkg-config fuse3 --libs` -lcrypto -lssl

SRC_DIR = src
CRYPTO_DIR = crypto
FS_DIR = src/fs
TEST_DIR = tests

SRCS = $(SRC_DIR)/encfs.c \
       $(CRYPTO_DIR)/aes.c \
       $(CRYPTO_DIR)/hash.c \
       $(FS_DIR)/path.c \
       $(FS_DIR)/block_meta.c \
       $(FS_DIR)/zk_proof.c \
       $(SRC_DIR)/logger.c \
       $(SRC_DIR)/globals.c

OBJS = $(SRCS:.c=.o)
TARGET = encfs

TEST_SRC = $(TEST_DIR)/test_crypto.c
TEST_TARGET = test_crypto
TEST_LDFLAGS = -lcmocka -lcrypto -lssl

FUZZ_SRC = $(TEST_DIR)/fuzz_target.c
FUZZ_OBJS = $(FS_DIR)/block_meta.o $(CRYPTO_DIR)/hash.o
FUZZ_TARGET = fuzz_target

.PHONY: all clean test integration-test full-test dashboard-test docker-test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Unit tests with cmocka
$(TEST_TARGET): $(TEST_SRC) $(filter-out $(SRC_DIR)/encfs.o, $(OBJS))
	$(CC) $(CFLAGS) $^ -o $@ $(TEST_LDFLAGS)

test: $(TEST_TARGET)
	@echo "=== Running Unit Tests ==="
	./$(TEST_TARGET)

# Integration test
integration-test: $(TARGET)
	@echo "=== Running Integration Tests ==="
	chmod +x $(TEST_DIR)/integration_test.sh
	./$(TEST_DIR)/integration_test.sh

# Full test suite (all scenarios)
full-test: $(TARGET)
	@echo "=== Running Full Test Suite ==="
	chmod +x $(TEST_DIR)/full_test_suite.sh
	./$(TEST_DIR)/full_test_suite.sh

# Dashboard tests
dashboard-test:
	@echo "=== Running Dashboard Tests ==="
	chmod +x $(TEST_DIR)/test_dashboard.sh
	./$(TEST_DIR)/test_dashboard.sh

# Docker-based testing
docker-test:
	@echo "=== Running Docker Tests ==="
	chmod +x $(TEST_DIR)/docker_test.sh
	./$(TEST_DIR)/docker_test.sh

# Fuzz target for AFL
$(FUZZ_TARGET): $(FUZZ_SRC) $(FUZZ_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# AFL fuzzing (requires afl-gcc)
fuzz: $(FUZZ_TARGET)
	@echo "Run with: afl-fuzz -i tests/fuzz_corpus -o tests/fuzz_out ./$(FUZZ_TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET) $(FUZZ_TARGET)
	rm -f encfs_perf.log test_results.log

# Help
help:
	@echo "EncFS Build Targets:"
	@echo "  make           - Build encfs binary"
	@echo "  make test      - Run unit tests (cmocka)"
	@echo "  make integration-test - Run integration tests"
	@echo "  make full-test - Run full test suite"
	@echo "  make dashboard-test - Test dashboard UI"
	@echo "  make docker-test - Run tests in Docker"
	@echo "  make fuzz      - Build AFL fuzz target"
	@echo "  make clean     - Remove build artifacts"

