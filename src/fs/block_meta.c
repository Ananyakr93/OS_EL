#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "../../include/fs/block_meta.h"

/* Helper: Hex string to bytes */
static int hex2bin(const char *hex, unsigned char *bin, size_t bin_len) {
    size_t i;
    for (i = 0; i < bin_len; i++) {
        if (!hex[2*i] || !hex[2*i+1]) return -1;
        sscanf(hex + 2*i, "%2hhx", &bin[i]);
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

int save_file_meta(const char *meta_path, const file_meta_t *meta) {
    FILE *fp = fopen(meta_path, "w");
    if (!fp) return -errno;

    char hex[65];
    bin2hex(meta->file_iv, 16, hex);
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"mode\": %d,\n", meta->mode);
    fprintf(fp, "  \"policy\": \"%s\",\n", meta->policy[0] ? meta->policy : "ALL");
    fprintf(fp, "  \"file_iv\": \"%s\",\n", hex);
    fprintf(fp, "  \"blocks\": [\n");
    
    for (size_t i = 0; i < meta->block_count; i++) {
        char iv_hex[33], tag_hex[33];
        bin2hex(meta->blocks[i].iv, 16, iv_hex);
        bin2hex(meta->blocks[i].tag, 16, tag_hex);
        
        fprintf(fp, "    { \"index\": %llu, \"iv\": \"%s\", \"tag\": \"%s\" }",
                (unsigned long long)meta->blocks[i].block_index, iv_hex, tag_hex);
        if (i < meta->block_count - 1) fprintf(fp, ",");
        fprintf(fp, "\n");
    }
    
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

/* Very basic JSON parser tailored to our format */
int load_file_meta(const char *meta_path, file_meta_t *meta) {
    FILE *fp = fopen(meta_path, "r");
    if (!fp) return -errno;
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *json = malloc(fsize + 1);
    if (!json) { fclose(fp); return -ENOMEM; }
    
    fread(json, 1, fsize, fp);
    json[fsize] = '\0';
    fclose(fp);
    
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
                char iv_hex[33] = {0}, tag_hex[33] = {0};
                
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
                
                block_meta_entry_t *entry = find_or_create_block_meta(meta, idx);
                if (entry) {
                    hex2bin(iv_hex, entry->iv, 16);
                    hex2bin(tag_hex, entry->tag, 16);
                }
                
                p++; /* Move past { */
            }
        }
    }
    
    free(json);
    return 0;
}
