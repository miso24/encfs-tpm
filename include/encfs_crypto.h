#ifndef INCLUDE_ENCFS_CRYPTO
#define INCLUDE_ENCFS_CRYPTO

#include <stddef.h>
#include <stdint.h>

int crypto_derive_key(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
int crypto_aes_encrypt(const uint8_t *key, const uint8_t *nonce,
        const uint8_t *in_data, int in_len,
        uint8_t *out_buf, int *out_len,
        uint8_t *out_tag);
int crypto_aes_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *in_tag,
        const uint8_t *in_data, int in_len,
        uint8_t *out_buf, int *out_len);
int crypto_getrandom(unsigned char *buf, int size);

#endif
