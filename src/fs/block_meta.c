#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>  /* For SHA256 */

#define HASH_SIZE SHA256_DIGEST_LENGTH

int load_block_meta(const char *meta_path, unsigned char *buffer, size_t data_len) {
    FILE *fp = fopen(meta_path, "rb");
    if (fp == NULL) {
        return -errno;
    }
    unsigned char stored_hash[HASH_SIZE];
    if (fread(stored_hash, 1, HASH_SIZE, fp) != HASH_SIZE) {
        fclose(fp);
        return -EIO;
    }
    size_t n = fread(buffer, 1, data_len, fp);
    if (n != data_len) {
        fclose(fp);
        return -EIO;
    }
    /* Compute and verify hash */
    unsigned char computed_hash[HASH_SIZE];
    SHA256(buffer, data_len, computed_hash);
    if (memcmp(stored_hash, computed_hash, HASH_SIZE) != 0) {
        fclose(fp);
        return -EILSEQ;  /* Integrity failure */
    }
    fclose(fp);
    return 0;
}

/* Add save_block_meta symmetrically if needed */
