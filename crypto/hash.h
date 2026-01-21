#ifndef HASH_H
#define HASH_H

#include <stddef.h>

void compute_sha256(const unsigned char *data, size_t len,
                    unsigned char *out_hash);

void sha256(const unsigned char *data,
            size_t len,
            unsigned char *out_hash);

#endif

