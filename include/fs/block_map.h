#ifndef BLOCK_MAP_H
#define BLOCK_MAP_H

#include <sys/types.h>

typedef struct {
    off_t offset;
    unsigned char hash[32];
    int encrypted;
} block_map_t;


#endif

