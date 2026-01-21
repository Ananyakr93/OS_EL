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

#include "../crypto/aes.h"
#include "../crypto/hash.h"
#include "../include/fs/path.h"
#include "../include/fs/block_meta.h"
#include "../include/globals.h"
#include "../include/logger.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

char *global_cipher_dir = NULL;
int default_enc_mode = MODE_SECURE; 

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
    struct encfs_ctx *ctx = malloc(sizeof(struct encfs_ctx));
    memset(ctx->master_key, 0x42, 32); 
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

static int encfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
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
    
    fh->meta.mode = default_enc_mode;
    strcpy(fh->meta.policy, "ALL"); /* Default */
    
    FILE *urf = fopen("/dev/urandom", "rb");
    if (urf) {
        fread(fh->meta.file_iv, 1, 16, urf);
        fclose(urf);
    }
    fh->dirty = 1;
    save_file_meta(fh->meta_path, &fh->meta);

    fi->fh = (uint64_t)fh;
    return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi) {
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

    if (load_file_meta(fh->meta_path, &fh->meta) < 0) {
        fh->meta.mode = default_enc_mode;
        strcpy(fh->meta.policy, "ALL");
    }

    fi->fh = (uint64_t)fh;
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

    size_t total_read = 0;
    while (total_read < size) {
        off_t current_offset = offset + total_read;
        uint64_t block_idx = current_offset / BLOCK_SIZE;
        size_t block_off = current_offset % BLOCK_SIZE;
        size_t to_read = BLOCK_SIZE - block_off;
        if (to_read > (size - total_read)) to_read = size - total_read;

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

            if (res != 0) return -EIO;
        } else {
            /* Unencrypted block logic */
            memcpy(dec_buf, file_buf, n);
            dec_len = n;
        }
        
        if (block_off + to_read > dec_len) {
             to_read = dec_len - block_off;
        }

        memcpy(buf + total_read, dec_buf + block_off, to_read);
        total_read += to_read;
        
        if ((size_t)n < BLOCK_SIZE) break;
    }

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

    size_t total_written = 0;
    while (total_written < size) {
        off_t current_offset = offset + total_written;
        uint64_t block_idx = current_offset / BLOCK_SIZE;
        size_t block_off = current_offset % BLOCK_SIZE;
        size_t to_write = BLOCK_SIZE - block_off;
        if (to_write > (size - total_written)) to_write = size - total_written;

        int do_enc = should_encrypt(block_idx, fh->meta.policy);

        unsigned char block_buf[BLOCK_SIZE];
        ssize_t n = pread(fh->fd, block_buf, BLOCK_SIZE, block_idx * BLOCK_SIZE);
        if (n < 0) n = 0;
        
        unsigned char plain_buf[BLOCK_SIZE];
        size_t plain_len = 0;
        block_meta_entry_t *bmeta = find_or_create_block_meta(&fh->meta, block_idx);
        
        if (n > 0) {
             size_t dlen;
             if (do_enc) {
                 if (fh->meta.mode == MODE_SECURE) {
                     aes_gcm_decrypt(block_buf, n, plain_buf, &dlen, ctx->master_key, bmeta->iv, bmeta->tag);
                 } else {
                     aes_ctr_decrypt(block_buf, n, plain_buf, &dlen, ctx->master_key, bmeta->iv);
                 }
                 plain_len = dlen;
             } else {
                 memcpy(plain_buf, block_buf, n);
                 plain_len = n;
             }
        } else {
            memset(plain_buf, 0, BLOCK_SIZE);
            plain_len = BLOCK_SIZE;
        }
        
        memcpy(plain_buf + block_off, buf + total_written, to_write);
        if (block_off + to_write > plain_len) plain_len = block_off + to_write;

        unsigned char enc_buf[BLOCK_SIZE];
        size_t enc_len;
        
        if (do_enc) {
            FILE *urf = fopen("/dev/urandom", "rb");
            if (urf) {
                fread(bmeta->iv, 1, 16, urf);
                fclose(urf);
            }

            int res = 0;
            if (fh->meta.mode == MODE_SECURE) {
                 res = aes_gcm_encrypt(plain_buf, plain_len, enc_buf, &enc_len, 
                                       ctx->master_key, bmeta->iv, bmeta->tag);
            } else {
                 res = aes_ctr_encrypt(plain_buf, plain_len, enc_buf, &enc_len,
                                       ctx->master_key, bmeta->iv);
            }
            if (res != 0) return -EIO;
        } else {
            memcpy(enc_buf, plain_buf, plain_len);
            enc_len = plain_len;
        }

        if (pwrite(fh->fd, enc_buf, enc_len, block_idx * BLOCK_SIZE) != (ssize_t)enc_len) {
            return -errno;
        }
        fh->dirty = 1;

        total_written += to_write;
    }

    gettimeofday(&end, NULL);
    getrusage(RUSAGE_SELF, &ru_end);
    log_performance("write", &start, &end, &ru_start, &ru_end);

    return total_written;
}

static int encfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    struct encfs_file_handle *fh = (struct encfs_file_handle *)fi->fh;
    if (fh) {
        if (fh->dirty) {
            save_file_meta(fh->meta_path, &fh->meta);
        }
        free_file_meta(&fh->meta);
        close(fh->fd);
        free(fh);
    }
    return 0;
}

static int encfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
    (void)flags;
    if (strcmp(name, "user.enc_policy") == 0) {
        char policy_val[64] = {0};
        if (size > 63) return -ERANGE;
        memcpy(policy_val, value, size);
        
        char real_path[PATH_MAX];
        get_real_path(path, real_path, sizeof(real_path));
        char meta_path[PATH_MAX + 32];
        snprintf(meta_path, sizeof(meta_path), "%s.meta", real_path);
        
        file_meta_t meta = {0};
        if (load_file_meta(meta_path, &meta) == 0) {
            if (strstr(policy_val, "Speed")) meta.mode = MODE_SPEED;
            else if (strstr(policy_val, "Secure")) meta.mode = MODE_SECURE;
            
            /* Check for HEAD:X */
            if (strncmp(policy_val, "HEAD:", 5) == 0 || strcmp(policy_val, "ALL") == 0) {
                strcpy(meta.policy, policy_val);
            }
            
            save_file_meta(meta_path, &meta);
            free_file_meta(&meta);
        }
        return 0;
    }
    return -ENOTSUP;
}

static struct fuse_operations encfs_oper = {
    .init    = encfs_init,
    .getattr = encfs_getattr,
    .readdir = encfs_readdir,
    .open    = encfs_open,
    .create  = encfs_create,
    .read    = encfs_read,
    .write   = encfs_write,
    .release = encfs_release,
    .setxattr = encfs_setxattr, 
};

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ciphertext-directory> <mountpoint> [FUSE options...]\n", argv[0]);
        return 1;
    }

    /* FUSE changes working directory to / when daemonizing.
       We must resolve the ciphertext path to an absolute path. */
    char *abs_cipher_dir = realpath(argv[1], NULL);
    if (!abs_cipher_dir) {
        perror("realpath ciphertext");
        return 1;
    }
    
    global_cipher_dir = abs_cipher_dir; /* realpath allocates memory */

    struct fuse_args args = FUSE_ARGS_INIT(argc - 1, argv + 1);
    int ret = fuse_main(args.argc, args.argv, &encfs_oper, NULL);
    
    free(global_cipher_dir);
    fuse_opt_free_args(&args);
    return ret;
}
