#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>
#include "encfs.h"
#include "encfs_crypto.h"

int crypto_derive_key(const uint8_t *kdk, size_t kdk_len,
                      const uint8_t *salt, size_t salt_len,
                      uint8_t *out_key, size_t out_key_len) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    OSSL_PARAM *param_ptr = params;
    int ret = 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        printf("Failed to fetch\n");
        return 1;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (kctx == NULL) {
        printf("Failed to create ctx\n");
        return 1;
    }

    *param_ptr++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
    *param_ptr++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)kdk, (size_t)kdk_len);
    *param_ptr++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "encfs-key", (size_t)9);
    *param_ptr++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, (size_t)salt_len);
    *param_ptr = OSSL_PARAM_construct_end();


    if (EVP_KDF_derive(kctx, out_key, out_key_len, params) <= 0) {
        printf("Failed to KDF derive\n");
        ret = 1;
    }

    EVP_KDF_CTX_free(kctx);
    return ret;
}

int crypto_aes_encrypt(const uint8_t *key, const uint8_t *nonce,
        const uint8_t *in_data, int in_len,
        uint8_t *out_buf, int *out_len,
        uint8_t *out_tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int tmp_len = 0;
    int lb_len = 0;
    int ret = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce)) {
        ret = 1;
        goto cleanup_aes_encrypt;
    }

    if (!EVP_EncryptUpdate(ctx, out_buf, &tmp_len, in_data, (int)in_len)) {
        ret = 1;
        goto cleanup_aes_encrypt;
    }

    if (!EVP_EncryptFinal_ex(ctx, out_buf + tmp_len, &lb_len)) {
        ret = 1;
        goto cleanup_aes_encrypt;
    }
    *out_len = tmp_len + lb_len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, ENCFS_TAG_SIZE, out_tag)) {
        ret = 1;
        goto cleanup_aes_encrypt;
    }

cleanup_aes_encrypt:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int crypto_aes_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *in_tag,
        const uint8_t *in_data, int in_len,
        uint8_t *out_buf, int *out_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int tmp_len = 0;
    int lb_len = 0;
    int ret = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce)) {
        ret = 1;
        goto cleanup_aes_decrypt;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ENCFS_TAG_SIZE, (void*)in_tag)) {
        ret = 1;
        goto cleanup_aes_decrypt;
    }

    if (!EVP_DecryptUpdate(ctx, out_buf, &tmp_len, in_data, (int)in_len)) {
        ret = 1;
        goto cleanup_aes_decrypt;
    }

    if (!EVP_DecryptFinal_ex(ctx, out_buf + tmp_len, &lb_len)) {
        ret = 1;
        goto cleanup_aes_decrypt;
    }
    *out_len = tmp_len + lb_len;

cleanup_aes_decrypt:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int crypto_getrandom(unsigned char *buf, int size) {
    if (RAND_bytes(buf, size) != 1) {
        return 1;
    }
    return 0;
}
