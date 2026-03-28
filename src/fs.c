#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include "encfs.h"
#include "encfs_fuse.h"
#include "encfs_crypto.h"
#include "fuse.h"

#define ENCFS_PATH(buf, state, path) \
    char buf[PATH_MAX]; \
    snprintf(buf, PATH_MAX, "%s/%s", (state)->encrypted_dir, (path))

size_t calc_raw_file_size(size_t file_size) {
    size_t enc_data_size, num_blocks, rem_data_size, raw_size;

    if (file_size < ENCFS_HEADER_SIZE) {
        return 0;
    }

    enc_data_size = file_size - ENCFS_HEADER_SIZE;
    num_blocks = enc_data_size / ENCFS_ENC_BLOCK_SIZE;
    rem_data_size = enc_data_size % ENCFS_ENC_BLOCK_SIZE;

    raw_size = num_blocks * ENCFS_BLOCK_SIZE;
    if (rem_data_size > ENCFS_NONCE_SIZE + ENCFS_TAG_SIZE) {
        raw_size += rem_data_size - ENCFS_NONCE_SIZE - ENCFS_TAG_SIZE;
    }

    return raw_size;
}

static void *encfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void)conn;

    if (!cfg->auto_cache) {
        cfg->entry_timeout = 0;
        cfg->attr_timeout = 0;
        cfg->negative_timeout = 0;
    }
    return fuse_get_context()->private_data;
}

static int encfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    int res;
    encfs_state_t *state = fuse_get_context()->private_data;

    ENCFS_PATH(encfs_path, state, path);

    res = lstat(encfs_path, stbuf);
    if (res == -1) {
        return -errno;
    }

    if (S_ISREG(stbuf->st_mode)) {
        stbuf->st_size = calc_raw_file_size(stbuf->st_size);
    }
    return 0;
}

static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    DIR *dp;
    struct dirent *de;
    encfs_state_t *state = fuse_get_context()->private_data;

    ENCFS_PATH(encfs_path, state, path);

    dp = opendir(encfs_path);
    if (dp == NULL) {
        return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
        struct stat st;

        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        if (filler(buf, de->d_name, &st, 0, 0)) {
            break;
        }
    }

    closedir(dp);
    return 0;
}

static int setup_encfs_file(encfs_state_t *state, int fd, const uint8_t *salt, struct fuse_file_info *fi) {
    encfs_file_t *file = NULL;
    int res;

    file = calloc(1, sizeof(encfs_file_t));
    if (file == NULL) {
        return -ENOMEM;
    }

    file->fd = fd;
    memcpy(file->salt, salt, ENCFS_SALT_SIZE);

    res = crypto_derive_key(state->kdk, ENCFS_KDK_SIZE, file->salt, ENCFS_SALT_SIZE, file->key, ENCFS_KEY_SIZE);
    if (res != 0) {
        free(file);
        return -EIO;
    }

    fi->fh = (uint64_t)file;
    return 0;
}

static int encfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    uint8_t salt[ENCFS_SALT_SIZE];
    int fd, res;

    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;

    ENCFS_PATH(encfs_path, state, path);

    fd = open(encfs_path, fi->flags, mode);
    if (fd == -1) {
        return -errno;
    }

    res = crypto_getrandom(salt, ENCFS_SALT_SIZE);
    if (res != 0) {
        close(fd);
        return -EIO;
    }

    uint8_t version = ENCFS_VERSION;
    write(fd, ENCFS_MAGIC, ENCFS_MAGIC_SIZE);
    write(fd, &version, ENCFS_VERSION_SIZE);

    res = write(fd, salt, ENCFS_SALT_SIZE);
    if (res != ENCFS_SALT_SIZE) {
        close(fd);
        return -EIO;
    }
    return setup_encfs_file(state, fd, salt, fi);
}

static int encfs_open(const char *path, struct fuse_file_info *fi) {
    uint8_t salt[ENCFS_SALT_SIZE];
    uint8_t header[ENCFS_HEADER_SIZE];
    int fd, n;

    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;

    ENCFS_PATH(encfs_path, state, path);

    fd = open(encfs_path, fi->flags);
    if (fd == -1) {
        return -errno;
    }

    read(fd, header, ENCFS_HEADER_SIZE);
    if (memcmp(header, ENCFS_MAGIC, ENCFS_MAGIC_SIZE) != 0 || header[ENCFS_VERSION_SIZE] != ENCFS_VERSION) {
        close(fd);
        return -EIO;
    }

    n = read(fd, salt, ENCFS_SALT_SIZE);
    if (n != ENCFS_SALT_SIZE) {
        close(fd);
        return -EIO;
    }

    return setup_encfs_file(state, fd, salt, fi);
}

static int encfs_release(const char *path, struct fuse_file_info *fi) {
    encfs_file_t *file = (encfs_file_t*)fi->fh;
    if (file != NULL) {
        memset(file->key, 0, ENCFS_KEY_SIZE);
        close(file->fd);
        free(file);
    }
    return 0;
}

static int encfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    encfs_file_t *file = (encfs_file_t*)fi->fh;
    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;

    ENCFS_PATH(encfs_path, state, path);

    // unimplemented

    return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    encfs_file_t *file = (encfs_file_t*)fi->fh;
    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;

    ENCFS_PATH(encfs_path, state, path);

    // unimplemented

    return 0;
}

struct fuse_operations encfs_ops = {
    .init = encfs_init,
    .getattr = encfs_getattr,
    .readdir = encfs_readdir,
    .create = encfs_create,
    .open = encfs_open,
    .write = encfs_write,
    .read = encfs_read,
    .release = encfs_release,
};
