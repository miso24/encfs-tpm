#ifndef INCLUDE_ENCFS_TPM_BACKEND
#define INCLUDE_ENCFS_TPM_BACKEND

#include <stddef.h>
#include <tss2_esys.h>
#include <tss2_tctildr.h>

typedef struct _tpm_context_t {
    ESYS_CONTEXT *esys_ctx;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    ESYS_TR primary_handle;
} tpm_context_t;

TSS2_RC tpm_initialize(tpm_context_t *, const char *);
TSS2_RC tpm_seal(tpm_context_t *, const uint8_t *, size_t, TPM2B_PUBLIC **, TPM2B_PRIVATE **);
TSS2_RC tpm_unseal(tpm_context_t *, TPM2B_PUBLIC *, TPM2B_PRIVATE *, TPM2B_SENSITIVE_DATA **);
TSS2_RC tpm_getrandom(tpm_context_t *, uint8_t *, size_t);
void tpm_finalize(tpm_context_t *);

int save_sealed_key(const char *, TPM2B_PUBLIC *, TPM2B_PRIVATE *);
int load_sealed_key(const char *, TPM2B_PUBLIC *, TPM2B_PRIVATE *);

static const TPM2B_PUBLIC primary_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN),
        .authPolicy = {
            .size = 0,
        },
        .parameters.rsaDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_CFB,
            },
            .scheme = {
                .scheme = TPM2_ALG_NULL,
            },
            .keyBits = 2048,
            .exponent = 0,
        },
        .unique.rsa = {
            .size = 0,
            .buffer = {},
        },
    }
};


#endif
