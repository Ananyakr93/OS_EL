#ifndef CONFIG_H
#define CONFIG_H

#define BLOCK_SIZE  4096
#define TAG_SIZE    16      // AES-GCM authentication tag
#define HASH_SIZE   32      // SHA-256

#define MODE_SPEED     0
#define MODE_SECURITY  1

extern int enc_mode;        // set at mount time

#endif
