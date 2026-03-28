#ifndef INCLUDE_ENCFS_FUSE
#define INCLUDE_ENCFS_FUSE

#include <stddef.h>
#include <fuse.h>
#include "encfs.h"

extern struct fuse_operations encfs_ops;

typedef struct encfs_file_t {
    uint8_t salt[ENCFS_SALT_SIZE];
    uint8_t key[ENCFS_KEY_SIZE];
    int fd;
} encfs_file_t;

#endif
