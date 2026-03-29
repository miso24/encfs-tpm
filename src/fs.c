#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdbool.h>
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

bool is_encfs_file(int fd) {
    struct stat st;
    char buf[ENCFS_HEADER_SIZE];

    if (fstat(fd, &st) == -1) {
        return false;
    }

    if (st.st_size < ENCFS_HEADER_SIZE) {
        return false;
    }

    ssize_t res = read(fd, buf, ENCFS_HEADER_SIZE);
    return res == ENCFS_HEADER_SIZE && memcmp(buf, ENCFS_MAGIC, ENCFS_MAGIC_SIZE) == 0;
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
    (void)fi;

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
    (void)offset;
    (void)fi;
    (void)flags;

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

    int flags = fi->flags;
    if ((flags & O_ACCMODE) == O_WRONLY) {
        flags = (flags & ~O_ACCMODE) | O_RDWR;
    }
    flags &= ~O_APPEND;

    fd = open(encfs_path, flags, mode);
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
    bool need_truncate;
    int fd, flags, n;

    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;

    ENCFS_PATH(encfs_path, state, path);

    flags = fi->flags;
    need_truncate = (flags & O_TRUNC) != 0;
    if ((flags & O_ACCMODE) == O_WRONLY) {
        flags = (flags & ~O_ACCMODE) | O_RDWR;
    }
    flags &= ~O_APPEND;
    flags &= ~O_TRUNC;

    fd = open(encfs_path, flags);
    if (fd == -1) {
        return -errno;
    }

    if (!is_encfs_file(fd)) {
        close(fd);
        return -EIO;
    }

    if (need_truncate) {
        ftruncate(fd, ENCFS_HEADER_SIZE);
    }

    n = pread(fd, salt, ENCFS_SALT_SIZE, ENCFS_PREAMBLE_SIZE);
    if (n != ENCFS_SALT_SIZE) {
        close(fd);
        return -EIO;
    }

    return setup_encfs_file(state, fd, salt, fi);
}

static int encfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;

    encfs_file_t *file = (encfs_file_t*)fi->fh;
    if (file != NULL) {
        memset(file->key, 0, ENCFS_KEY_SIZE);
        close(file->fd);
        free(file);
    }
    return 0;
}

static int encfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    uint8_t nonce[ENCFS_NONCE_SIZE];
    uint8_t tag[ENCFS_TAG_SIZE];
    uint8_t plain[ENCFS_BLOCK_SIZE];
    uint8_t enc[ENCFS_BLOCK_SIZE];
    uint8_t enc_block[ENCFS_ENC_BLOCK_SIZE];
    encfs_file_t *file = (encfs_file_t*)fi->fh;
    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;
    struct stat st;
    int start_block, num_blocks;
    int raw_num_blocks, raw_offset;
    size_t raw_size;
    size_t bytes_written = 0;

    ENCFS_PATH(encfs_path, state, path);

    lstat(encfs_path, &st);
    raw_size = calc_raw_file_size(st.st_size);
    raw_num_blocks = (raw_size + ENCFS_BLOCK_SIZE - 1) / ENCFS_BLOCK_SIZE;

    start_block = offset / ENCFS_BLOCK_SIZE;
    num_blocks = ((offset % ENCFS_BLOCK_SIZE) + size + ENCFS_BLOCK_SIZE - 1) / ENCFS_BLOCK_SIZE;

    for (int i = 0; i < num_blocks; i++) {
        int block_start = (i == 0) ? offset % ENCFS_BLOCK_SIZE : 0;
        int block_end = (i == num_blocks - 1) ? ((offset + size - 1) % ENCFS_BLOCK_SIZE) + 1 : ENCFS_BLOCK_SIZE;
        int block_idx = start_block + i;
        bool in_partial_block = (raw_size != 0) && ((block_start != 0) || (block_end != ENCFS_BLOCK_SIZE));
        int write_len = block_end - block_start;
        int plain_len = 0;
        int enc_len, enc_size;

        raw_offset = ENCFS_HEADER_SIZE + block_idx * ENCFS_ENC_BLOCK_SIZE;
        memset(plain, 0, ENCFS_BLOCK_SIZE);

        if (in_partial_block) {
            uint8_t enc_buf[ENCFS_ENC_BLOCK_SIZE];
            bool is_last_block = i == raw_num_blocks - 1;
            size_t raw_data_size = (is_last_block) ? raw_size % ENCFS_BLOCK_SIZE : ENCFS_BLOCK_SIZE;
            size_t enc_size = raw_data_size + ENCFS_NONCE_SIZE + ENCFS_TAG_SIZE;
            pread(file->fd, enc_buf, enc_size, raw_offset);

            uint8_t *nonce_ptr = enc_buf;
            uint8_t *tag_ptr = enc_buf + ENCFS_NONCE_SIZE;
            uint8_t *enc_ptr = tag_ptr + ENCFS_TAG_SIZE;

            crypto_aes_decrypt(file->key, nonce_ptr, tag_ptr, enc_ptr, raw_data_size, plain, &plain_len);
        }

        memcpy(plain + block_start, buf + bytes_written, write_len);
        if (block_start + write_len > plain_len) {
            plain_len = block_start + write_len;
        }

        crypto_getrandom(nonce, ENCFS_NONCE_SIZE);
        crypto_aes_encrypt(file->key, nonce, plain, plain_len, enc, &enc_len, tag);

        memcpy(enc_block, nonce, ENCFS_NONCE_SIZE);
        memcpy(enc_block + ENCFS_NONCE_SIZE, tag, ENCFS_TAG_SIZE);
        memcpy(enc_block + ENCFS_NONCE_SIZE + ENCFS_TAG_SIZE, enc, enc_len);

        enc_size = ENCFS_NONCE_SIZE + ENCFS_TAG_SIZE + enc_len;
        pwrite(file->fd, enc_block, enc_size, raw_offset);

        bytes_written += write_len;
    }

    return bytes_written;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    uint8_t enc_buf[ENCFS_ENC_BLOCK_SIZE];
    uint8_t plain[ENCFS_BLOCK_SIZE];

    encfs_file_t *file = (encfs_file_t*)fi->fh;
    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;
    struct stat st;
    int start_block, num_blocks;
    int raw_num_blocks, raw_offset;
    size_t raw_size;
    size_t bytes_read = 0;

    ENCFS_PATH(encfs_path, state, path);

    lstat(encfs_path, &st);
    raw_size = calc_raw_file_size(st.st_size);
    raw_num_blocks = (raw_size + ENCFS_BLOCK_SIZE - 1) / ENCFS_BLOCK_SIZE;

    if (size > raw_size) {
        size = raw_size;
    }

    start_block = offset / ENCFS_BLOCK_SIZE;
    num_blocks = ((offset % ENCFS_BLOCK_SIZE) + size + ENCFS_BLOCK_SIZE - 1) / ENCFS_BLOCK_SIZE;

    for (int i = 0; i < num_blocks; i++) {
        int block_start = (i == 0) ? offset % ENCFS_BLOCK_SIZE : 0;
        int block_end = (i == num_blocks - 1) ? ((offset + size - 1) % ENCFS_BLOCK_SIZE) + 1 : ENCFS_BLOCK_SIZE;
        int block_idx = start_block + i;
        bool is_last_block = i == raw_num_blocks - 1;
        size_t read_len = (is_last_block) ? block_end - block_start : ENCFS_BLOCK_SIZE;
        size_t enc_data_len = read_len + ENCFS_NONCE_SIZE + ENCFS_TAG_SIZE;
        int plain_len;

        raw_offset = ENCFS_HEADER_SIZE + block_idx * ENCFS_ENC_BLOCK_SIZE;

        pread(file->fd, enc_buf, enc_data_len, raw_offset);

        uint8_t *nonce_ptr = enc_buf;
        uint8_t *tag_ptr = enc_buf + ENCFS_NONCE_SIZE;
        uint8_t *enc_ptr = enc_buf + ENCFS_NONCE_SIZE + ENCFS_TAG_SIZE;

        crypto_aes_decrypt(file->key, nonce_ptr, tag_ptr, enc_ptr, read_len, plain, &plain_len);

        memcpy(buf + bytes_read, plain + block_start, read_len);
        bytes_read += read_len;
    }

    return bytes_read;
}

int truncate_regular_file(int fd, off_t size) {
    int res;

    res = ftruncate(fd, size);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int encfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    encfs_file_t *file = NULL;
    encfs_state_t *state = (encfs_state_t*)fuse_get_context()->private_data;
    bool need_close = false;
    int fd, res;

    ENCFS_PATH(encfs_path, state, path);

    if (fi != NULL) {
        file = (encfs_file_t*)fi->fh;
        fd = file->fd;
    } else {
        fd = open(encfs_path, O_RDWR);
        if (!is_encfs_file(fd)) {
            res = truncate_regular_file(fd, size);
            close(fd);
            return res;
        }
        need_close = true;
    }

    if (size == 0) {
        ftruncate(fd, ENCFS_HEADER_SIZE);
    } else {
        // unimplemented
        return -ENOSYS;
    }

    if (need_close) {
        close(fd);
    }
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
    .truncate = encfs_truncate,
};
