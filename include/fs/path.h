#ifndef ENCFS_FS_PATH_H
#define ENCFS_FS_PATH_H

#include <stddef.h>     
#include <errno.h>    

int get_real_path(const char *vfs_path, char *out_real_path, size_t bufsize);

int build_meta_path(const char *real_path, char *meta_path, size_t bufsize);

void get_storage_path(const char *path, char *real_path);

#endif 
