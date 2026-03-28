#ifndef INCLUDE_ENCFS_H
#define INCLUDE_ENCFS_H

#include <stdint.h>

#define ENCFS_BLOCK_SIZE 4096
#define ENCFS_SALT_SIZE 16
#define ENCFS_TAG_SIZE 16
#define ENCFS_NONCE_SIZE 12
#define ENCFS_KDK_SIZE 32
#define ENCFS_KEY_SIZE 32
#define ENCFS_ENC_BLOCK_SIZE (ENCFS_BLOCK_SIZE + ENCFS_TAG_SIZE + ENCFS_NONCE_SIZE)

#define ENCFS_DEFAULT_KEY_NAME "key.bin"
#define ENCFS_DEFAULT_TCTI "swtpm:path=/tmp/myswtpm/swtpm.sock"

#define ENCFS_MAGIC "EFS"
#define ENCFS_MAGIC_SIZE 3
#define ENCFS_VERSION 1
#define ENCFS_VERSION_SIZE 1
#define ENCFS_PREAMBLE_SIZE (ENCFS_MAGIC_SIZE + ENCFS_VERSION_SIZE)
#define ENCFS_HEADER_SIZE (ENCFS_MAGIC_SIZE + ENCFS_VERSION_SIZE + ENCFS_SALT_SIZE)

typedef struct _encfs_state_t {
    uint8_t kdk[ENCFS_KDK_SIZE];
    char *encrypted_dir;
    char *tcti;
} encfs_state_t;

#endif
