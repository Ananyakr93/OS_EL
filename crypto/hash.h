#ifndef HASH_H
#define HASH_H

#include <stddef.h>

void compute_sha256(const unsigned char *data, size_t len,
                    unsigned char *out_hash);

void sha256(const unsigned char *data,
            size_t len,
            unsigned char *out_hash);

void compute_hmac_sha256(const void *key, size_t key_len,
                         const unsigned char *data, size_t data_len,
                         unsigned char *out_mac);

int derive_key_pbkdf2(const char *passphrase, const unsigned char *salt, size_t salt_len,
                      int iterations, unsigned char *out_key, size_t key_len);

#endif
