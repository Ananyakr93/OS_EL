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
#include <stddef.h>
#include "../crypto/aes.h"
#include "../crypto/hash.h"
#include "../include/fs/path.h"
#include "../include/fs/block_meta.h"
#include "../include/globals.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

char *global_cipher_dir = NULL;
int enc_mode = 1; /* Assume 1 == AES-256-GCM; set via args if needed */

struct encfs_priv {
    char meta_path[PATH_MAX];
    unsigned char key[32];    
    unsigned char iv[12]; 
};

static void *encfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void)conn;
    cfg->kernel_cache = 1;
    return NULL;
}

static int encfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;

    char real_path[PATH_MAX];
    int r = get_real_path(path, real_path, sizeof(real_path));
    if (r < 0) return r;

    if (lstat(real_path, stbuf) == -1) {
        return -errno;
    }
    return 0;
}

static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;

    char real_path[PATH_MAX];
    int r = get_real_path(path, real_path, sizeof(real_path));
    if (r < 0) return r;

    DIR *dp = opendir(real_path);
    if (!dp) return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strstr(de->d_name, ".meta") || strstr(de->d_name, ".tag")) continue;

        struct stat st = {0};
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }

    closedir(dp);
    return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi) {
    char real_path[PATH_MAX];
    int r = get_real_path(path, real_path, sizeof(real_path));
    if (r < 0) return r;

    int fd = open(real_path, fi->flags);
    if (fd == -1) return -errno;

    fi->fh = fd;
    return 0;
}

static int encfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct encfs_priv *priv = fuse_get_context()->private_data;
    char meta_path[PATH_MAX];
    /* Construct meta_path */
    snprintf(meta_path, sizeof(meta_path), "%s.meta", path); /* Stub */
    size_t len = strlen(meta_path);
    if (len >= PATH_MAX) {
        return -ENAMETOOLONG;
    }
    memcpy(priv->meta_path, meta_path, len);
    priv->meta_path[len] = '\0';
    /* Create underlying file */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd == -1) {
        return -errno;
    }
    fi->fh = fd;
    return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void)path;
    struct encfs_priv *priv = fuse_get_context()->private_data;
    char tag_path[PATH_MAX];
    int ret = snprintf(tag_path, sizeof(tag_path), "%s.tag", priv->meta_path);
    if (ret < 0 || (size_t)ret >= sizeof(tag_path)) {
        return -ENAMETOOLONG;
    }

    unsigned char enc_buf[4096];
    ssize_t enc_len = pread(fi->fh, enc_buf, size, offset);
    if (enc_len <= 0) {
        return enc_len == 0 ? 0 : -errno;
    }

    if (enc_mode == 1) {
        size_t dec_len = 0;
        unsigned char tag[16];    

        ret = aes_gcm_decrypt(enc_buf, (size_t)enc_len,
                              (unsigned char *)buf, &dec_len,
                              priv->key, priv->iv, tag);
        if (ret != 0) {
            return -EIO;
        }
        return (int)dec_len;
    }

    memcpy(buf, enc_buf, enc_len);
    return (int)enc_len;
}

static int encfs_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
    (void)path;
    struct encfs_priv *priv = fuse_get_context()->private_data;

    unsigned char enc_buf[4096];
    size_t enc_len = 0;
    unsigned char tag[16];        

    if (enc_mode == 1) {
        int ret = aes_gcm_encrypt((const unsigned char *)buf, size,
                                  enc_buf, &enc_len,
                                  priv->key, priv->iv, tag);
        if (ret != 0) {
            return -EIO;
        }
    } else {
        enc_len = size;
        memcpy(enc_buf, buf, size);
    }

    if (pwrite(fi->fh, enc_buf, enc_len, offset) != (ssize_t)enc_len) {
        return -errno;
    }


    return (int)size;
}

static struct fuse_operations encfs_oper = {
    .init    = encfs_init,
    .getattr = encfs_getattr,
    .readdir = encfs_readdir,
    .open    = encfs_open,
    .create  = encfs_create,
    .read    = encfs_read,
    .write   = encfs_write,
};


int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ciphertext-directory> <mountpoint> [FUSE options...]\n", argv[0]);
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s ./ciphertext ./fuse-mount\n", argv[0]);
        fprintf(stderr, "  %s ./ciphertext ./fuse-mount -f -d\n", argv[0]);
        return 1;
    }

    /* argv[1] = ciphertext directory */
    global_cipher_dir = strdup(argv[1]);
    if (!global_cipher_dir) {
        perror("strdup ciphertext dir");
        return 1;
    }

    /* Pass everything from argv[2] onward to fuse_main:
       argv[2] = mountpoint, argv[3..] = -f -d -o ... etc. */
    struct fuse_args args = FUSE_ARGS_INIT(argc - 1, argv + 1);

    int ret = fuse_main(args.argc, args.argv, &encfs_oper, NULL);

    free(global_cipher_dir);
    global_cipher_dir = NULL;
    fuse_opt_free_args(&args);

    return ret;
}
