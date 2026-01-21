#include <stdio.h>
#include <string.h>
#include <limits.h>     /* PATH_MAX */
#include <errno.h>      /* ENAMETOOLONG, EINVAL */

#include "../../include/fs/path.h"
#include "../../include/globals.h"

int get_real_path(const char *vfs_path, char *real_path, size_t bufsize)
{
    if (vfs_path == NULL || real_path == NULL || bufsize < 2)
        return -EINVAL;

    /* Root ("/" or empty path) maps directly to the backing root directory */
    if (strcmp(vfs_path, "/") == 0 || *vfs_path == '\0')
    {
        size_t root_len = strlen(global_cipher_dir);

        if (root_len + 1 >= bufsize)
            return -ENAMETOOLONG;

        memcpy(real_path, global_cipher_dir, root_len);
        real_path[root_len] = '\0';

        /* Optional: ensure trailing slash if your storage layout requires it */
        if (root_len > 0 && real_path[root_len - 1] != '/')
        {
            if (root_len + 2 > bufsize)
                return -ENAMETOOLONG;
            real_path[root_len] = '/';
            real_path[root_len + 1] = '\0';
        }

        return 0;
    }

    const char *p = (*vfs_path == '/') ? vfs_path + 1 : vfs_path;
    int n = snprintf(real_path, bufsize, "%s/%s", global_cipher_dir, p);

    if (n < 0 || (size_t)n >= bufsize)
        return -ENAMETOOLONG;

    return 0;
}

void get_storage_path(const char *path, char *real_path)
{
    snprintf(real_path, PATH_MAX, "%s%s",
             global_cipher_dir ? global_cipher_dir : ".",
             path && *path == '/' ? path + 1 : path);
}

int build_meta_path(const char *real_path, char *meta_path, size_t bufsize)
{
    if (!real_path || !meta_path || bufsize < 6) return -EINVAL;

    size_t len = strlen(real_path);
    if (len + 6 > bufsize) {
        meta_path[0] = '\0';
        return -ENAMETOOLONG;
    }

    memcpy(meta_path, real_path, len);
    memcpy(meta_path + len, ".meta", 6);  /* includes NUL */

    return 0;
}
