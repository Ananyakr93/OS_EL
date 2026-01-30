#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/file.h>
#include "../../include/fs/block_meta.h"
#include "../../crypto/hash.h"

/* Helper: Hex string to bytes */
static int hex2bin(const char *hex, unsigned char *bin, size_t bin_len) {
    size_t i;
    for (i = 0; i < bin_len; i++) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) return -1;
        bin[i] = (unsigned char)v;
    }
    return 0;
}

/* Helper: Bytes to hex string */
static void bin2hex(const unsigned char *bin, size_t bin_len, char *hex) {
    size_t i;
    for (i = 0; i < bin_len; i++) {
        sprintf(hex + 2*i, "%02x", bin[i]);
    }
    hex[2*bin_len] = '\0';
}

void free_file_meta(file_meta_t *meta) {
    if (meta->blocks) {
        free(meta->blocks);
        meta->blocks = NULL;
    }
    meta->block_count = 0;
}

block_meta_entry_t *find_or_create_block_meta(file_meta_t *meta, uint64_t block_index) {
    for (size_t i = 0; i < meta->block_count; i++) {
        if (meta->blocks[i].block_index == block_index) {
            return &meta->blocks[i];
        }
    }
    /* Not found, expand array */
    size_t new_count = meta->block_count + 1;
    block_meta_entry_t *new_blocks = realloc(meta->blocks, new_count * sizeof(block_meta_entry_t));
    if (!new_blocks) return NULL;
    
    meta->blocks = new_blocks;
    meta->block_count = new_count;
    
    block_meta_entry_t *entry = &meta->blocks[new_count - 1];
    memset(entry, 0, sizeof(block_meta_entry_t));
    entry->block_index = block_index;
    return entry;
}

int save_file_meta(const char *meta_path, const file_meta_t *meta, const unsigned char *master_key) {
    FILE *fp = fopen(meta_path, "w+"); // w+ to read back for HMAC
    if (!fp) return -errno;
    
    if (flock(fileno(fp), LOCK_EX) != 0) {
        fclose(fp);
        return -errno;
    }

    char hex[65];
    bin2hex(meta->file_iv, 16, hex);
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"mode\": %d,\n", meta->mode);
    fprintf(fp, "  \"policy\": \"%s\",\n", meta->policy[0] ? meta->policy : "ALL");
    fprintf(fp, "  \"file_iv\": \"%s\",\n", hex);
    fprintf(fp, "  \"blocks\": [\n");
    
    for (size_t i = 0; i < meta->block_count; i++) {
        char iv_hex[33], tag_hex[33], hash_hex[65];
        bin2hex(meta->blocks[i].iv, 16, iv_hex);
        bin2hex(meta->blocks[i].tag, 16, tag_hex);
        bin2hex(meta->blocks[i].block_hash, 32, hash_hex);
        
        fprintf(fp, "    { \"index\": %llu, \"iv\": \"%s\", \"tag\": \"%s\", \"hash\": \"%s\" }",
                (unsigned long long)meta->blocks[i].block_index, iv_hex, tag_hex, hash_hex);
        if (i < meta->block_count - 1) fprintf(fp, ",");
        fprintf(fp, "\n");
    }
    
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    
    // Now compute HMAC of what we just wrote
    fflush(fp);
    long json_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    unsigned char *buf = malloc(json_len);
    if (!buf) { fclose(fp); return -ENOMEM; }
    
    if (fread(buf, 1, json_len, fp) != (size_t)json_len) {
        free(buf); fclose(fp); return -EIO;
    }
    
    unsigned char mac[32];
    compute_hmac_sha256(master_key, 32, buf, json_len, mac);
    free(buf);
    
    fseek(fp, 0, SEEK_END);
    char mac_hex[65];
    bin2hex(mac, 32, mac_hex);
    
    // Append HMAC
    fprintf(fp, "%s", mac_hex);
    
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    return 0;
}

/* Very basic JSON parser tailored to our format */
int load_file_meta(const char *meta_path, file_meta_t *meta, const unsigned char *master_key) {
    FILE *fp = fopen(meta_path, "r");
    if (!fp) return -errno;
    
    if (flock(fileno(fp), LOCK_SH) != 0) {
        fclose(fp);
        return -errno;
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (fsize < 64) { // Needs at least HMAC
         flock(fileno(fp), LOCK_UN);
         fclose(fp);
         return -EACCES; // Invalid format
    }

    char *file_buf = malloc(fsize + 1);
    if (!file_buf) { flock(fileno(fp), LOCK_UN); fclose(fp); return -ENOMEM; }
    
    fread(file_buf, 1, fsize, fp);
    file_buf[fsize] = '\0';
    
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    
    // Last 64 bytes should be HMAC hex
    // Data is everything before that.
    long data_len = fsize - 64;
    char *stored_mac_hex = file_buf + data_len;
    
    unsigned char computed_mac[32];
    compute_hmac_sha256(master_key, 32, (unsigned char*)file_buf, data_len, computed_mac);
    
    char computed_mac_hex[65];
    bin2hex(computed_mac, 32, computed_mac_hex);
    
    if (strncmp(stored_mac_hex, computed_mac_hex, 64) != 0) {
        free(file_buf);
        return -EACCES; /* Integrity check failed */
    }
    
    /* Integrity OK, parse JSON */
    /* Null terminate the JSON part effectively */
    file_buf[data_len] = '\0';
    char *json = file_buf;
    
    memset(meta, 0, sizeof(file_meta_t));
    
    /* Parse mode */
    char *p = strstr(json, "\"mode\"");
    if (p) {
        p = strchr(p, ':');
        if (p) meta->mode = atoi(p + 1);
    }

    /* Parse policy */
    p = strstr(json, "\"policy\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                char *end = strchr(p + 1, '"');
                if (end) {
                    size_t len = end - (p + 1);
                    if (len > 31) len = 31;
                    strncpy(meta->policy, p + 1, len);
                    meta->policy[len] = '\0';
                }
            }
        }
    }
    
    /* Parse file_iv */
    p = strstr(json, "\"file_iv\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                char hex[33];
                strncpy(hex, p + 1, 32);
                hex[32] = '\0';
                hex2bin(hex, meta->file_iv, 16);
            }
        }
    }
    
    /* Parse blocks */
    p = strstr(json, "\"blocks\"");
    if (p) {
        p = strchr(p, '[');
        if (p) {
            /* Loop through objects */
            while ((p = strchr(p, '{'))) {
                uint64_t idx = 0;
                char iv_hex[33] = {0}, tag_hex[33] = {0}, hash_hex[65] = {0};
                
                char *q = strstr(p, "\"index\"");
                if (q) {
                    q = strchr(q, ':');
                    if (q) idx = strtoull(q + 1, NULL, 10);
                }
                
                q = strstr(p, "\"iv\"");
                if (q) {
                    q = strchr(q, ':');
                    if (q) {
                        q = strchr(q, '"');
                        if (q) {
                            int k = 0;
                            q++;
                            while (isxdigit(*q) && k < 32) iv_hex[k++] = *q++;
                        }
                    }
                }
                
                q = strstr(p, "\"tag\"");
                if (q) {
                    q = strchr(q, ':');
                    if (q) {
                        q = strchr(q, '"');
                        if (q) {
                             int k = 0;
                            q++;
                            while (isxdigit(*q) && k < 32) tag_hex[k++] = *q++;
                        }
                    }
                }

                q = strstr(p, "\"hash\"");
                if (q) {
                    q = strchr(q, ':');
                    if (q) {
                        q = strchr(q, '"');
                        if (q) {
                             int k = 0;
                            q++;
                            while (isxdigit(*q) && k < 64) hash_hex[k++] = *q++;
                        }
                    }
                }
                
                block_meta_entry_t *entry = find_or_create_block_meta(meta, idx);
                if (entry) {
                    hex2bin(iv_hex, entry->iv, 16);
                    hex2bin(tag_hex, entry->tag, 16);
                    hex2bin(hash_hex, entry->block_hash, 32);
                }
                
                p++; /* Move past { */
            }
        }
    }
    
    free(file_buf);
    return 0;
}
