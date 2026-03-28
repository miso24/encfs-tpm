#include <stdio.h>
#include <string.h>
#include <tss2_mu.h>
#include "encfs_tpm.h"

TSS2_RC tpm_initialize(tpm_context_t *ctx, const char *tcti_conf) {
    TPM2B_DATA outside_info = {
        .size = 0,
        .buffer = {},
    };
    TPML_PCR_SELECTION creation_pcr = { .count = 0 };
    TPM2B_SENSITIVE_CREATE in_sensitive = { .size = 0 };
    TSS2_RC rc;

    ctx->esys_ctx = NULL;
    ctx->tcti_ctx = NULL;
    ctx->primary_handle = ESYS_TR_NONE;

    rc = Tss2_TctiLdr_Initialize(tcti_conf, &ctx->tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize TctiLdr\n");
        return rc;
    }

    rc = Esys_Initialize(&ctx->esys_ctx, ctx->tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize Esys\n");
        tpm_finalize(ctx);
        return rc;
    }

    rc = Esys_Startup(ctx->esys_ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        fprintf(stderr, "Failed to Esys_Startup\n");
        tpm_finalize(ctx);
        return rc;
    }

    rc = Esys_CreatePrimary(ctx->esys_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &in_sensitive, &primary_template, &outside_info, &creation_pcr,
        &ctx->primary_handle, NULL, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to Esys_CreatePrimary\n");
        tpm_finalize(ctx);
        return rc;
    }

    return TSS2_RC_SUCCESS;
}

void tpm_finalize(tpm_context_t *ctx) {
    if (ctx->primary_handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys_ctx, ctx->primary_handle);
    }
    if (ctx->esys_ctx != NULL) {
        Esys_Finalize(&ctx->esys_ctx);
    }
    if (ctx->tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&ctx->tcti_ctx);
    }
}

TSS2_RC tpm_seal(tpm_context_t *ctx, const uint8_t *data, size_t size,
                 TPM2B_PUBLIC **out_public, TPM2B_PRIVATE **out_private)
{
    TPMT_SYM_DEF policy_algo = {
        .algorithm = TPM2_ALG_AES,
        .keyBits.aes = 128,
        .mode.aes = TPM2_ALG_CFB,
    };
    TPM2B_DIGEST pcr_digest = { .size = 0 };
    TPM2B_DIGEST *policy_digest = NULL;
    TPML_PCR_SELECTION pcr_sel = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = { 1, 0, 0 },
        }},
    };
    TPM2B_SENSITIVE_CREATE in_sensitive = {
        .sensitive = {
            .userAuth = { .size = 0 },
            .data = { .size = size },
        },
    };
    TPM2B_DATA outside_info = { .size = 0 };
    TPML_PCR_SELECTION creation_pcr = { .count = 0 };
    ESYS_TR session_handle = ESYS_TR_NONE;
    TSS2_RC rc;
 
    memcpy(in_sensitive.sensitive.data.buffer, data, size);
 
    rc = Esys_StartAuthSession(ctx->esys_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            NULL, TPM2_SE_TRIAL, &policy_algo, TPM2_ALG_SHA256,
            &session_handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to start trial session: 0x%x\n", rc);
        return rc;
    }
 
    rc = Esys_PolicyPCR(ctx->esys_ctx, session_handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &pcr_digest, &pcr_sel);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to PolicyPCR: 0x%x\n", rc);
        goto cleanup_tpm_seal;
    }
 
    rc = Esys_PolicyGetDigest(ctx->esys_ctx, session_handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &policy_digest);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to PolicyGetDigest: 0x%x\n", rc);
        goto cleanup_tpm_seal;
    }
 
    Esys_FlushContext(ctx->esys_ctx, session_handle);
    session_handle = ESYS_TR_NONE;
 
    TPM2B_PUBLIC in_public = {
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .authPolicy = *policy_digest,
            .objectAttributes = (
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT
            ),
            .parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL,
        },
    };
 
    Esys_Free(policy_digest);
    policy_digest = NULL;
 
    rc = Esys_Create(ctx->esys_ctx, ctx->primary_handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &in_sensitive, &in_public, &outside_info, &creation_pcr,
            out_private, out_public, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to Create: 0x%x\n", rc);
        return rc;
    }
 
    return TSS2_RC_SUCCESS;
 
cleanup_tpm_seal:
    if (session_handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys_ctx, session_handle);
    }
    Esys_Free(policy_digest);
    return rc;
}

TSS2_RC tpm_unseal(tpm_context_t *ctx, TPM2B_PUBLIC *in_public, TPM2B_PRIVATE *in_private, TPM2B_SENSITIVE_DATA **out_data) {
    TPMT_SYM_DEF policy_algo = {
        .algorithm = TPM2_ALG_AES,
        .keyBits.aes = 128,
        .mode.aes = TPM2_ALG_CFB,
    };
    TPM2B_DIGEST pcr_digest = { .size = 0 };
    TPML_PCR_SELECTION pcr_sel = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = { 1, 0, 0 },
        }},
    };
    ESYS_TR key_handle = ESYS_TR_NONE;
    ESYS_TR session_handle = ESYS_TR_NONE;
    TSS2_RC rc;

    rc = Esys_Load(ctx->esys_ctx, ctx->primary_handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            in_private, in_public, &key_handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to load: 0x%x\n", rc);
        return rc;
    }

    rc = Esys_StartAuthSession(ctx->esys_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            NULL, TPM2_SE_POLICY, &policy_algo, TPM2_ALG_SHA256,
            &session_handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to start trial session: 0x%x\n", rc);
        goto cleanup_tpm_unseal;
    }
 
    rc = Esys_PolicyPCR(ctx->esys_ctx, session_handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &pcr_digest, &pcr_sel);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to PolicyPCR: 0x%x\n", rc);
        goto cleanup_tpm_unseal;
    }

    rc = Esys_Unseal(ctx->esys_ctx, key_handle,
            session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
            out_data);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to unseal: 0x%x\n", rc);
        goto cleanup_tpm_unseal;
    }

    Esys_FlushContext(ctx->esys_ctx, key_handle);
    Esys_FlushContext(ctx->esys_ctx, session_handle);
    return TSS2_RC_SUCCESS;

cleanup_tpm_unseal:
    if (session_handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys_ctx, session_handle);
    }

    if (key_handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys_ctx, key_handle);
    }
    return rc;
}

TSS2_RC tpm_getrandom(tpm_context_t *ctx, uint8_t *buf, size_t size) {
    TPM2B_DIGEST *random_bytes = NULL;
    TSS2_RC rc;

    rc = Esys_GetRandom(ctx->esys_ctx, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE,
            size, &random_bytes);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to getrandom: 0x%x\n", rc);
        return rc;
    }

    memcpy(buf, random_bytes->buffer, random_bytes->size);

    Esys_Free(random_bytes);
    return rc;
}

int save_sealed_key(const char *path, TPM2B_PUBLIC *in_public, TPM2B_PRIVATE *in_private) {
    FILE *fp = NULL;
    uint8_t *buf = NULL;
    size_t buf_size = sizeof(TPM2B_PUBLIC) + sizeof(TPM2B_PRIVATE);
    size_t offset = 0;
    size_t n;
    int ret = 0;
    TSS2_RC rc;

    buf = (uint8_t*)malloc(buf_size);
    if (buf == NULL) {
        ret = 1;
        goto cleanup_save_sealed_key;
    }

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(in_public, buf, buf_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        ret = 1;
        goto cleanup_save_sealed_key;
    }
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(in_private, buf, buf_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        ret = 1;
        goto cleanup_save_sealed_key;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        ret = 1;
        goto cleanup_save_sealed_key;
    }
    n = fwrite(buf, 1, offset, fp);
    if (n != offset) {
        ret = 1;
    }

cleanup_save_sealed_key:
    if (fp != NULL) {
        fclose(fp);
    }
    if (buf != NULL) {
        free(buf);
    }
    return ret;
}

int load_sealed_key(const char *path, TPM2B_PUBLIC *out_public, TPM2B_PRIVATE *out_private) {
    FILE *fp = NULL;
    uint8_t *buf = NULL;
    size_t max_size = sizeof(TPM2B_PUBLIC) + sizeof(TPM2B_PRIVATE);
    size_t offset = 0;
    size_t n;
    int ret = 0;
    TSS2_RC rc;

    buf = (uint8_t*)malloc(max_size);
    if (buf == NULL) {
        ret = 1;
        goto cleanup_load_sealed_key;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        ret = 1;
        goto cleanup_load_sealed_key;
    }
    n = fread(buf, 1, max_size, fp);
    if (n == 0) {
        ret = 1;
        goto cleanup_load_sealed_key;
    }

    rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(buf, n, &offset, out_public);
    if (rc != TSS2_RC_SUCCESS) {
        ret = 1;
        goto cleanup_load_sealed_key;
    }
    rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(buf, n, &offset, out_private);
    if (rc != TSS2_RC_SUCCESS) {
        ret = 1;
        goto cleanup_load_sealed_key;
    }

cleanup_load_sealed_key:
    if (fp != NULL) {
        fclose(fp);
    }
    if (buf != NULL) {
        free(buf);
    }
    return ret;
}
