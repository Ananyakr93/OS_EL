CC = gcc
CFLAGS = -Wall -Wextra -g `pkg-config fuse3 --cflags` -I./include
LDFLAGS = `pkg-config fuse3 --libs` -lcrypto -lssl

SRC_DIR = src
CRYPTO_DIR = crypto
FS_DIR = src/fs

SRCS = $(SRC_DIR)/encfs.c \
       $(CRYPTO_DIR)/aes.c \
       $(CRYPTO_DIR)/hash.c \
       $(FS_DIR)/path.c \
       $(FS_DIR)/block_meta.c \
       $(SRC_DIR)/logger.c

OBJS = $(SRCS:.c=.o)
TARGET = encfs

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
