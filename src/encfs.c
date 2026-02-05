#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stddef.h>
#include <linux/limits.h>
#include <ctype.h>
#include <pthread.h>
#include <utime.h>
#include <openssl/rand.h>

#include "../crypto/aes.h"
#include "../crypto/hash.h"
#include "../include/fs/path.h"
#include "../include/fs/block_meta.h"
#include "../include/fs/zk_proof.h"
#include "../include/globals.h"
#include "../include/logger.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define SUPERBLOCK_SIZE 32768
#define BLOCKS_PER_SUPER 8
int default_enc_mode = MODE_SECURE; 

struct encfs_config {
    char *passphrase;
    char *mode;
};

struct encfs_ctx {
    unsigned char master_key[32];
};

struct encfs_file_handle {
    int fd;
    char path[PATH_MAX];
    char meta_path[PATH_MAX];
    file_meta_t meta;
    int dirty;
    int open_flags;
    pthread_mutex_t mutex;
};

#define ENCFS_OPT(t, p, v) { t, offsetof(struct encfs_config, p), v }

static struct fuse_opt encfs_opts[] = {
    ENCFS_OPT("passphrase=%s", passphrase, 0),
    ENCFS_OPT("mode=%s", mode, 0),
    FUSE_OPT_END
};

static struct encfs_ctx *get_ctx() {
    return (struct encfs_ctx *)fuse_get_context()->private_data;
}

static int should_encrypt(uint64_t block_idx, const char *policy) {
    if (!policy || !*policy || strcmp(policy, "ALL") == 0) return 1;
    if (strncmp(policy, "HEAD:", 5) == 0) {
        int limit = atoi(policy + 5);
        if (block_idx < (uint64_t)limit) return 1;
        return 0;
    }
    return 1; /* Default to encrypt if unknown policy */
}

static void *encfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void)conn;
    cfg->kernel_cache = 1;
    cfg->use_ino = 1; /* Enable multi-threading support for inodes */
    /* Big writes are essential for superblock optimization */
    // cfg->big_writes = 1; (implicit in newer FUSE usually, but can't set in 3.x via struct field easily without fuse_loop config)
    struct encfs_ctx *ctx = (struct encfs_ctx *)fuse_get_context()->private_data;
    return ctx;
}

static int encfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;
    if (lstat(real_path, stbuf) == -1) return -errno;
    return 0;
}

static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;

    DIR *dp = opendir(real_path);
    if (!dp) return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len > 5 && strcmp(de->d_name + len - 5, ".meta") == 0) continue;

        struct stat st = {0};
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    closedir(dp);
    return 0;
}

static int encfs_mkdir(const char *path, mode_t mode) {
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;

    if (mkdir(real_path, mode) == -1) return -errno;
    return 0;
}

static int encfs_rmdir(const char *path) {
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;

    if (rmdir(real_path) == -1) return -errno;
    return 0;
}

static int encfs_unlink(const char *path) {
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;

    char meta_path[PATH_MAX + 32];
    snprintf(meta_path, sizeof(meta_path), "%s.meta", real_path);
    unlink(meta_path); 

    if (unlink(real_path) == -1) return -errno;
    return 0;
}

static int encfs_rename(const char *from, const char *to, unsigned int flags) {
    if (flags) return -EINVAL; 
    char real_from[PATH_MAX];
    char real_to[PATH_MAX];
    if (get_real_path(from, real_from, sizeof(real_from)) < 0) return -ENAMETOOLONG;
    if (get_real_path(to, real_to, sizeof(real_to)) < 0) return -ENAMETOOLONG;

    char meta_from[PATH_MAX + 32];
    snprintf(meta_from, sizeof(meta_from), "%s.meta", real_from);
    char meta_to[PATH_MAX + 32];
    snprintf(meta_to, sizeof(meta_to), "%s.meta", real_to);

    rename(meta_from, meta_to); 

    if (rename(real_from, real_to) == -1) return -errno;
    return 0;
}

static int encfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;
    
    if (truncate(real_path, size) == -1) return -errno;
    return 0;
}

static int encfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;

    if (fi && fi->fh) {
        struct encfs_file_handle *fh = (struct encfs_file_handle *)fi->fh;
        if (futimens(fh->fd, tv) == -1) return -errno;
    } else {
        if (utimensat(AT_FDCWD, real_path, tv, 0) == -1) return -errno;
    }
    return 0;
}

static int encfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct encfs_ctx *ctx = get_ctx();
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;

    int fd = open(real_path, O_RDWR | O_CREAT | O_EXCL, mode);
    if (fd == -1) return -errno;

    char meta_path_name[PATH_MAX + 32];
    snprintf(meta_path_name, sizeof(meta_path_name), "%s.meta", real_path);

    struct encfs_file_handle *fh = calloc(1, sizeof(struct encfs_file_handle));
    fh->fd = fd;
    strcpy(fh->path, real_path);
    strcpy(fh->meta_path, meta_path_name);
    fh->open_flags = fi->flags;
    pthread_mutex_init(&fh->mutex, NULL);
    
    fh->meta.mode = default_enc_mode;
    strcpy(fh->meta.policy, "ALL"); 
    
    // Generate secure random IV for file
    if (RAND_bytes(fh->meta.file_iv, 16) != 1) {
        pthread_mutex_destroy(&fh->mutex);
        free(fh);
        close(fd);
        return -EIO;
    }
    
    fh->dirty = 1;
    save_file_meta(fh->meta_path, &fh->meta, ctx->master_key);

    fi->fh = (uint64_t)fh;
    return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi) {
    struct encfs_ctx *ctx = get_ctx();
    char real_path[PATH_MAX];
    if (get_real_path(path, real_path, sizeof(real_path)) < 0) return -ENAMETOOLONG;

    int fd = open(real_path, fi->flags);
    if (fd == -1) return -errno;

    char meta_path_name[PATH_MAX + 32];
    snprintf(meta_path_name, sizeof(meta_path_name), "%s.meta", real_path);

    struct encfs_file_handle *fh = calloc(1, sizeof(struct encfs_file_handle));
    fh->fd = fd;
    strcpy(fh->path, real_path);
    strcpy(fh->meta_path, meta_path_name);
    fh->open_flags = fi->flags;
    pthread_mutex_init(&fh->mutex, NULL);

    int res = load_file_meta(fh->meta_path, &fh->meta, ctx->master_key);
    if (res < 0) {
        pthread_mutex_destroy(&fh->mutex);
        free(fh);
        close(fd);
        return res;
    }

    fi->fh = (uint64_t)fh;
    return 0;
}

static int encfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    (void)path;
    struct encfs_ctx *ctx = get_ctx();
    struct encfs_file_handle *fh = (struct encfs_file_handle *)fi->fh;
    if (fh) {
        pthread_mutex_lock(&fh->mutex);
        if (fh->dirty) {
             save_file_meta(fh->meta_path, &fh->meta, ctx->master_key);
             fh->dirty = 0;
        }
        int res = isdatasync ? fdatasync(fh->fd) : fsync(fh->fd);
        pthread_mutex_unlock(&fh->mutex);
        if (res == -1) return -errno;
    }
    return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void)path;
    struct encfs_file_handle *fh = (struct encfs_file_handle *)fi->fh;
    struct encfs_ctx *ctx = get_ctx();
    struct timeval start, end;
    struct rusage ru_start, ru_end;

    gettimeofday(&start, NULL);
    getrusage(RUSAGE_SELF, &ru_start);
    
    pthread_mutex_lock(&fh->mutex);

    /* Prefetching for Speed Mode */
    if (fh->meta.mode == MODE_SPEED) {
        posix_fadvise(fh->fd, offset, size * 2, POSIX_FADV_SEQUENTIAL);
    }

    size_t total_read = 0;
    while (total_read < size) {
        off_t current_offset = offset + total_read;
        size_t rem = size - total_read;
        
        /* Hybrid Block Compilation (Superblock Read) */
        /* If we have a large remaining request and are aligned to start of a block, try efficient bulk read */
        if (rem >= SUPERBLOCK_SIZE && (current_offset % BLOCK_SIZE) == 0 && fh->meta.mode == MODE_SPEED) {
             uint64_t start_block_idx = current_offset / BLOCK_SIZE;
             unsigned char superval_buf[SUPERBLOCK_SIZE];
             
             ssize_t n = pread(fh->fd, superval_buf, SUPERBLOCK_SIZE, start_block_idx * BLOCK_SIZE);
             if (n <= 0) break;

             // Log superblock hit?
             // log_msg("Superblock read: %ld bytes\n", n);

             size_t processed = 0;
             int error = 0;
             
             // Process each 4KB block inside the superblock
             size_t n_size = (size_t)n;
             for (size_t b = 0; b < n_size; b += BLOCK_SIZE) {
                 size_t chunk = BLOCK_SIZE;
                 if (b + chunk > n_size) chunk = n_size - b;
                 
                 uint64_t blk_idx = start_block_idx + (b / BLOCK_SIZE);
                 unsigned char dec_chunk[BLOCK_SIZE];
                 size_t dec_len = 0;
                 
                 if (should_encrypt(blk_idx, fh->meta.policy)) {
                     block_meta_entry_t *bmeta = find_or_create_block_meta(&fh->meta, blk_idx);
                     unsigned char iv[16];
                     memcpy(iv, bmeta->iv, 16);
                     
                     int res = 0;
                     if (fh->meta.mode == MODE_SECURE) {
                         res = aes_gcm_decrypt(superval_buf + b, chunk, dec_chunk, &dec_len, 
                                               ctx->master_key, iv, bmeta->tag);
                     } else {
                         res = aes_ctr_decrypt(superval_buf + b, chunk, dec_chunk, &dec_len,
                                               ctx->master_key, iv);
                     }
                     if (res != 0) { error = -EIO; break; }

                     unsigned char hash[32];
                     compute_sha256(dec_chunk, dec_len, hash);
                     unsigned char zero_hash[32] = {0};
                     if (memcmp(bmeta->block_hash, zero_hash, 32) != 0) {
                         if (memcmp(hash, bmeta->block_hash, 32) != 0) {
                             error = -EIO; break; 
                         }
                     }
                 } else {
                     memcpy(dec_chunk, superval_buf + b, chunk);
                     dec_len = chunk;
                 }
                 
                 memcpy(buf + total_read + b, dec_chunk, dec_len);
                 processed += dec_len;
             }
             
             if (error) {
                 pthread_mutex_unlock(&fh->mutex);
                 return error;
             }
             
             total_read += processed;
             if (n_size < SUPERBLOCK_SIZE) break; // EOF hit inside superblock
             continue; 
        }

        /* Fallback: Standard 4KB Block Processing */
        uint64_t block_idx = current_offset / BLOCK_SIZE;
        size_t block_off = current_offset % BLOCK_SIZE;
        size_t to_read = BLOCK_SIZE - block_off;
        if (to_read > rem) to_read = rem;

        unsigned char file_buf[BLOCK_SIZE];
        ssize_t n = pread(fh->fd, file_buf, BLOCK_SIZE, block_idx * BLOCK_SIZE);
        if (n <= 0) break; 
        
        unsigned char dec_buf[BLOCK_SIZE];
        size_t dec_len = 0;
        
        if (should_encrypt(block_idx, fh->meta.policy)) {
            block_meta_entry_t *bmeta = find_or_create_block_meta(&fh->meta, block_idx);
            unsigned char iv[16];
            memcpy(iv, bmeta->iv, 16);
            
            int res = 0;
            if (fh->meta.mode == MODE_SECURE) {
                res = aes_gcm_decrypt(file_buf, n, dec_buf, &dec_len, 
                                      ctx->master_key, iv, bmeta->tag);
            } else {
                res = aes_ctr_decrypt(file_buf, n, dec_buf, &dec_len,
                                      ctx->master_key, iv);
            }

            if (res != 0) {
                pthread_mutex_unlock(&fh->mutex);
                return -EIO;
            }
            
            unsigned char hash[32];
            compute_sha256(dec_buf, dec_len, hash);
            unsigned char zero_hash[32] = {0};
            if (memcmp(bmeta->block_hash, zero_hash, 32) != 0) {
                 if (memcmp(hash, bmeta->block_hash, 32) != 0) {
                     pthread_mutex_unlock(&fh->mutex);
                     return -EIO;
                 }
            }

        } else {
            memcpy(dec_buf, file_buf, n);
            dec_len = n;
        }
        
        if (block_off + to_read > dec_len) {
             to_read = dec_len > block_off ? dec_len - block_off : 0;
        }

        memcpy(buf + total_read, dec_buf + block_off, to_read);
        total_read += to_read;
        
        if ((size_t)n < BLOCK_SIZE) break;
    }

    pthread_mutex_unlock(&fh->mutex);

    gettimeofday(&end, NULL);
    getrusage(RUSAGE_SELF, &ru_end);
    log_performance("read", &start, &end, &ru_start, &ru_end);

    return total_read;
}

static int encfs_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
    (void)path;
    struct encfs_file_handle *fh = (struct encfs_file_handle *)fi->fh;
    struct encfs_ctx *ctx = get_ctx();
    struct timeval start, end;
    struct rusage ru_start, ru_end;

    gettimeofday(&start, NULL);
    getrusage(RUSAGE_SELF, &ru_start);

    pthread_mutex_lock(&fh->mutex);

    size_t total_written = 0;
    while (total_written < size) {
        off_t current_offset = offset + total_written;
        size_t rem = size - total_written;

        // Superblock Write
        if (rem >= SUPERBLOCK_SIZE && (current_offset % BLOCK_SIZE) == 0 && fh->meta.mode == MODE_SPEED) {
             unsigned char super_dst[SUPERBLOCK_SIZE];
             uint64_t start_idx = current_offset / BLOCK_SIZE;
             int error = 0;

             for (int i=0; i<BLOCKS_PER_SUPER; i++) {
                 uint64_t idx = start_idx + i;
                 const char *src_chunk = buf + total_written + (i * BLOCK_SIZE);
                 unsigned char *dst_chunk = super_dst + (i * BLOCK_SIZE);
                 
                 block_meta_entry_t *bmeta = find_or_create_block_meta(&fh->meta, idx);
                 int do_enc = should_encrypt(idx, fh->meta.policy);
                 
                 if (do_enc) {
                     unsigned char pbuf[BLOCK_SIZE];
                     memcpy(pbuf, src_chunk, BLOCK_SIZE);
                     compute_sha256(pbuf, BLOCK_SIZE, bmeta->block_hash);
                     
                     if (RAND_bytes(bmeta->iv, 16) != 1) { error = -EIO; break; }
                     
                     size_t enc_len = 0;
                     int res = 0;
                     if (fh->meta.mode == MODE_SECURE) {
                         res = aes_gcm_encrypt(pbuf, BLOCK_SIZE, dst_chunk, &enc_len, 
                                               ctx->master_key, bmeta->iv, bmeta->tag);
                     } else {
                         res = aes_ctr_encrypt(pbuf, BLOCK_SIZE, dst_chunk, &enc_len,
                                               ctx->master_key, bmeta->iv);
                     }
                     if (res != 0) { error = -EIO; break; }

                 } else {
                      memcpy(dst_chunk, src_chunk, BLOCK_SIZE);
                 }
             }
             
             if (error) {
                 pthread_mutex_unlock(&fh->mutex);
                 return error;
             }
             
             // Batch write the superblock
             if (pwrite(fh->fd, super_dst, SUPERBLOCK_SIZE, start_idx * BLOCK_SIZE) != SUPERBLOCK_SIZE) {
                 pthread_mutex_unlock(&fh->mutex);
                 return -errno;
             }
             fh->dirty = 1;

             total_written += SUPERBLOCK_SIZE;
             continue;
        }

        // Standard 4KB
        uint64_t block_idx = current_offset / BLOCK_SIZE;
        size_t block_off = current_offset % BLOCK_SIZE;
        size_t to_write = BLOCK_SIZE - block_off;
        if (to_write > (size - total_written)) to_write = size - total_written;

        int do_enc = should_encrypt(block_idx, fh->meta.policy);

        unsigned char block_buf[BLOCK_SIZE];
        ssize_t n = pread(fh->fd, block_buf, BLOCK_SIZE, block_idx * BLOCK_SIZE);
        if (n < 0) n = 0;
        
        unsigned char plain_buf[BLOCK_SIZE];
        size_t plain_len = BLOCK_SIZE; 
        
        block_meta_entry_t *bmeta = find_or_create_block_meta(&fh->meta, block_idx);
        
        if (n > 0) {
             size_t dlen;
             if (do_enc) {
                 if (fh->meta.mode == MODE_SECURE) {
                     aes_gcm_decrypt(block_buf, n, plain_buf, &dlen, ctx->master_key, bmeta->iv, bmeta->tag);
                 } else {
                     aes_ctr_decrypt(block_buf, n, plain_buf, &dlen, ctx->master_key, bmeta->iv);
                 }
                 if (dlen < BLOCK_SIZE) {
                     memset(plain_buf + dlen, 0, BLOCK_SIZE - dlen);
                 }
             } else {
                 memcpy(plain_buf, block_buf, n);
                 if ((size_t)n < BLOCK_SIZE) {
                     memset(plain_buf + n, 0, BLOCK_SIZE - n);
                 }
             }
        } else {
            memset(plain_buf, 0, BLOCK_SIZE);
            if (do_enc) {
                if (RAND_bytes(bmeta->iv, 16) != 1) {
                    pthread_mutex_unlock(&fh->mutex);
                    return -EIO;
                }
            }
        }
        
        memcpy(plain_buf + block_off, buf + total_written, to_write);
        
        /* Calculate Hash of the updated plaintext block */
        if (do_enc) {
            compute_sha256(plain_buf, BLOCK_SIZE, bmeta->block_hash);
        }

        unsigned char enc_buf[BLOCK_SIZE];
        size_t enc_len;
        
        if (do_enc) {
            if (RAND_bytes(bmeta->iv, 16) != 1) {
                pthread_mutex_unlock(&fh->mutex);
                return -EIO;
            }

            int res = 0;
            if (fh->meta.mode == MODE_SECURE) {
                 res = aes_gcm_encrypt(plain_buf, plain_len, enc_buf, &enc_len, 
                                       ctx->master_key, bmeta->iv, bmeta->tag);
            } else {
                 res = aes_ctr_encrypt(plain_buf, plain_len, enc_buf, &enc_len,
                                       ctx->master_key, bmeta->iv);
            }
            if (res != 0) {
                pthread_mutex_unlock(&fh->mutex);
                return -EIO;
            }
        } else {
            memcpy(enc_buf, plain_buf, plain_len);
            enc_len = plain_len;
        }

        if (pwrite(fh->fd, enc_buf, enc_len, block_idx * BLOCK_SIZE) != (ssize_t)enc_len) {
            pthread_mutex_unlock(&fh->mutex);
            return -errno;
        }
        fh->dirty = 1;

        total_written += to_write;
    }
    
    pthread_mutex_unlock(&fh->mutex);

    gettimeofday(&end, NULL);
    getrusage(RUSAGE_SELF, &ru_end);
    log_performance("write", &start, &end, &ru_start, &ru_end);

    return total_written;
}

static int encfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    struct encfs_ctx *ctx = get_ctx();
    struct encfs_file_handle *fh = (struct encfs_file_handle *)fi->fh;
    if (fh) {
        pthread_mutex_lock(&fh->mutex);
        if (fh->dirty) {
            save_file_meta(fh->meta_path, &fh->meta, ctx->master_key);
        }
        pthread_mutex_unlock(&fh->mutex);
        pthread_mutex_destroy(&fh->mutex);
        free_file_meta(&fh->meta);
        close(fh->fd);
        free(fh);
    }
    return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value, size_t size) {
    /* Implement ZK Proof Retrieval */
    if (strcmp(name, "user.zk_proof") == 0) {
        /* Generate proof for this file */
        /* To do so, we need to load meta, get the first block's IV and ciphertext, and the master key */
        struct encfs_ctx *ctx = get_ctx();
        char real_path[PATH_MAX];
        get_real_path(path, real_path, sizeof(real_path));
        
        char meta_path[PATH_MAX + 32];
        snprintf(meta_path, sizeof(meta_path), "%s.meta", real_path);
        
        file_meta_t meta = {0};
        if (load_file_meta(meta_path, &meta, ctx->master_key) < 0) {
            return -EIO;
        }
        
        if (meta.block_count == 0) {
            free_file_meta(&meta);
            return -ENODATA;
        }

        /* Use block 0 for proof */
        block_meta_entry_t *bmeta = &meta.blocks[0];
        
        char proof[128] = {0};
        int res = zk_generate_proof(NULL, 0, ctx->master_key, bmeta->iv, proof, sizeof(proof));
        
        free_file_meta(&meta);
        
        if (res < 0) return -EIO;
        
        if (size == 0) return strlen(proof);
        if (size < strlen(proof) + 1) return -ERANGE;
        
        strcpy(value, proof);
        return strlen(proof);
    }
    
    /* Fallback to underlying FS if needed? No, usually xattrs on fuse are for custom things */
    return -ENODATA;
}


static int encfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
    (void)flags;
    struct encfs_ctx *ctx = get_ctx();
    if (strcmp(name, "user.enc_policy") == 0) {
        char policy_val[64] = {0};
        if (size > 63) return -ERANGE;
        memcpy(policy_val, value, size);
        
        int handled = 0;
        int new_mode = -1;
        char new_policy[32] = {0};
        
        if (strcmp(policy_val, "Speed") == 0) {
             new_mode = MODE_SPEED;
             handled = 1;
        } else if (strcmp(policy_val, "Secure") == 0) {
             new_mode = MODE_SECURE;
             handled = 1;
        } else if (strcmp(policy_val, "ALL") == 0) {
             strcpy(new_policy, "ALL");
             handled = 1;
        } else if (strncmp(policy_val, "HEAD:", 5) == 0) {
             char *end;
             long val = strtol(policy_val + 5, &end, 10);
             if (*end == '\0' && val >= 0) {
                 strcpy(new_policy, policy_val);
                 handled = 1;
             }
        }
        
        if (!handled) return -EINVAL;

        char real_path[PATH_MAX];
        get_real_path(path, real_path, sizeof(real_path));
        char meta_path[PATH_MAX + 32];
        snprintf(meta_path, sizeof(meta_path), "%s.meta", real_path);
        
        file_meta_t meta = {0};
        if (load_file_meta(meta_path, &meta, ctx->master_key) == 0) {
            if (new_mode != -1) meta.mode = new_mode;
            if (new_policy[0]) strcpy(meta.policy, new_policy);
            
            save_file_meta(meta_path, &meta, ctx->master_key);
            free_file_meta(&meta);
        } else {
             // Failed to load meta?
             return -EIO;
        }
        return 0;
    }
    return -ENOTSUP;
}

static struct fuse_operations encfs_oper = {
    .init    = encfs_init,
    .getattr = encfs_getattr,
    .readdir = encfs_readdir,
    .mkdir   = encfs_mkdir,
    .rmdir   = encfs_rmdir,
    .unlink  = encfs_unlink,
    .rename  = encfs_rename,
    .truncate= encfs_truncate,
    .open    = encfs_open,
    .create  = encfs_create,
    .read    = encfs_read,
    .write   = encfs_write,
    .fsync   = encfs_fsync,
    .release = encfs_release,
    .getxattr= encfs_getxattr,
    .setxattr= encfs_setxattr,
    .utimens = encfs_utimens,
};

static int encfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    (void)data; (void)outargs;
    if (key == FUSE_OPT_KEY_NONOPT && global_cipher_dir == NULL) {
        char *abs = realpath(arg, NULL);
        if (abs) {
            global_cipher_dir = abs;
            return 0; // Consume the argument so FUSE doesn't see it
        } else {
            fprintf(stderr, "Error: Cipher directory '%s' not found or invalid.\n", arg);
            return -1;
        }
    }
    return 1; // Keep the argument (e.g., the mountpoint)
}

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct encfs_config conf = {0};

    // Parse options: our custom ones + consume the cipher_dir
    if (fuse_opt_parse(&args, &conf, encfs_opts, encfs_opt_proc) == -1) {
        return 1;
    }
    
    if (global_cipher_dir == NULL) {
        fprintf(stderr, "Usage: %s <cipher_dir> <mountpoint> [options]\n", argv[0]);
        return 1;
    }

    if (conf.mode) {
        if (strcmp(conf.mode, "speed") == 0) default_enc_mode = MODE_SPEED;
        else if (strcmp(conf.mode, "secure") == 0) default_enc_mode = MODE_SECURE;
        else {
            fprintf(stderr, "Invalid mode: %s. Use 'speed' or 'secure'.\n", conf.mode);
            return 1;
        }
    }

    struct encfs_ctx ctx_data;
    if (conf.passphrase) {
        const char *salt = "ENCFS_SALT_CONST"; // Hardcoded salt for now
        if (derive_key_pbkdf2(conf.passphrase, (unsigned char*)salt, strlen(salt), 10000, 
                              ctx_data.master_key, 32) != 1) {
             fprintf(stderr, "Key derivation failed\n");
             return 1;
        }
    } else {
        fprintf(stderr, "Warning: No passphrase provided. Using default key (ZERO).\n");
        memset(ctx_data.master_key, 0x42, 32);
    }
    
    // Pass ctx_data to fuse_main via user_data argument
    int ret = fuse_main(args.argc, args.argv, &encfs_oper, &ctx_data);
    
    if (global_cipher_dir) free(global_cipher_dir);
    fuse_opt_free_args(&args);
    return ret;
}
