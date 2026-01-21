#ifndef ENCFS_BLOCK_META_H
#define ENCFS_BLOCK_META_H

#include <stddef.h>     /* size_t */
#include <stdint.h>     
#define BLOCK_META_HASH_SIZE 32


typedef struct {
    uint64_t           block_id;                    /* use 64-bit for large files */
    unsigned char      hash[BLOCK_META_HASH_SIZE];
} block_meta_entry_t;


int save_block_meta(const char *meta_path,
                    const block_meta_entry_t *table,
                    size_t count);

int load_block_meta(const char *meta_path,
                    block_meta_entry_t **table,
                    size_t *count);

#endif
