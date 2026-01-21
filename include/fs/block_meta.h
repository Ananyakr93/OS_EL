#ifndef ENCFS_BLOCK_META_H
#define ENCFS_BLOCK_META_H

#include <stddef.h>
#include <stdint.h>

#define MODE_SPEED  0
#define MODE_SECURE 1

#define BLOCK_SIZE 4096

typedef struct {
    uint64_t block_index;
    unsigned char iv[16];   /* Max needed for CTR is 16, GCM is 12 */
    unsigned char tag[16];  /* GCM tag */
} block_meta_entry_t;

typedef struct {
    int mode;
    char policy[32]; /* e.g. "ALL", "HEAD:10" */
    unsigned char file_iv[16];
    size_t block_count;
    block_meta_entry_t *blocks; /* Dynamic array */
} file_meta_t;

/* Load metadata from a JSON file into a file_meta_t structure.
   Returns 0 on success, negative errno on failure. */
int load_file_meta(const char *meta_path, file_meta_t *meta);

/* Save file_meta_t structure to a JSON file.
   Returns 0 on success, negative errno on failure. */
int save_file_meta(const char *meta_path, const file_meta_t *meta);

/* Helper to free the allocated blocks in meta */
void free_file_meta(file_meta_t *meta);

/* Helper to find a block entry, or create if not exists (if create_flag is set) */
block_meta_entry_t *find_or_create_block_meta(file_meta_t *meta, uint64_t block_index);

#endif
