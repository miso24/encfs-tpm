#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fuse.h>
#include <tss2_esys.h>

#include "encfs.h"
#include "encfs_tpm.h"
#include "encfs_fuse.h"
#include "fuse_opt.h"

#define ENCFS_OPT(k, t, v) { k, offsetof(encfs_state_t, t), v }

enum {
    OPT_KEY_HELP,
    OPT_KEY_encrypted_dir,
    OPT_KEY_TCTI,
};

static struct fuse_opt encfs_opts[] = {
    FUSE_OPT_KEY("-h", OPT_KEY_HELP),
    FUSE_OPT_KEY("--help", OPT_KEY_HELP),
    ENCFS_OPT("-e %s", encrypted_dir, 0),
    ENCFS_OPT("--encrypted-path %s", encrypted_dir, 0),
    ENCFS_OPT("--tcti %s", tcti, 0),
    FUSE_OPT_END
};

int generate_new_kdk(tpm_context_t *ctx, const char *key_path) {
    TPM2B_PUBLIC *public = NULL;
    TPM2B_PRIVATE *private = NULL;
    uint8_t kdk[ENCFS_KDK_SIZE];
    TSS2_RC rc;
    int ret = 0;

    rc = tpm_getrandom(ctx, kdk, ENCFS_KDK_SIZE);
    if (rc != TSS2_RC_SUCCESS) {
        return 1;
    }

    rc = tpm_seal(ctx, kdk, ENCFS_KDK_SIZE, &public, &private);
    if (rc != TSS2_RC_SUCCESS) {
        ret = 1;
        goto cleanup_generate_new_kdk;
    }

    if (save_sealed_key(key_path, public, private)) {
        ret = 1;
    }

cleanup_generate_new_kdk:
    memset(kdk, 0, ENCFS_KDK_SIZE);
    if (public != NULL) {
        Esys_Free(public);
    }
    if (private != NULL) {
        Esys_Free(private);
    }
    return ret;
}

int initialize_state(encfs_state_t *state, const char *tcti_conf, const char *key_path) {
    tpm_context_t tpm_ctx;
    TPM2B_PUBLIC public = { .size = 0 };
    TPM2B_PRIVATE private = { .size = 0 };
    TPM2B_SENSITIVE_DATA *kdk = NULL;
    TSS2_RC rc;
    int ret = 0;

    rc = tpm_initialize(&tpm_ctx, tcti_conf);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize TPM\n");
        return 1;
    }

    if (access(key_path, F_OK) == -1) {
        if (generate_new_kdk(&tpm_ctx, key_path) != 0) {
            ret = 1;
            goto cleanup_initialize_state;
        }
    }

    if (load_sealed_key(ENCFS_DEFAULT_KEY_NAME, &public, &private) !=0 ) {
        ret = 1;
        goto cleanup_initialize_state;
    }

    rc = tpm_unseal(&tpm_ctx, &public, &private, &kdk);
    if (rc != TSS2_RC_SUCCESS) {
        ret = 1;
        goto cleanup_initialize_state;
    }
    memcpy(state->kdk, kdk->buffer, kdk->size);

cleanup_initialize_state:
    if (kdk != NULL) {
        Esys_Free(kdk);
    }
    tpm_finalize(&tpm_ctx);
    return ret;
}

static int encfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    encfs_state_t *state = (encfs_state_t *)data;
    switch (key) {
        case OPT_KEY_HELP:
            fuse_opt_add_arg(outargs, "-h");
            fuse_main(outargs->argc, outargs->argv, &encfs_ops, NULL);
            exit(1);
    }
    return 1;
}

int main(int argc, char **argv) {
    encfs_state_t state;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int ret;

    memset(&state, 0, sizeof(encfs_state_t));
    fuse_opt_parse(&args, &state, encfs_opts, encfs_opt_proc);

    if (state.tcti == NULL) {
        state.tcti = strdup(ENCFS_DEFAULT_TCTI);
    }

    if (state.encrypted_dir == NULL) {
        ret = 1;
        fprintf(stderr, "encrypted_dir is not set\n");
        goto cleanup_main;
    }

    if (initialize_state(&state, state.tcti, ENCFS_DEFAULT_KEY_NAME) != 0) {
        ret = 1;
        fprintf(stderr, "Failed to initialize\n");
        goto cleanup_main;
    }

    ret = fuse_main(args.argc, args.argv, &encfs_ops, &state);

cleanup_main:
    memset(&state, 0, sizeof(encfs_state_t));
    fuse_opt_free_args(&args);
    if (state.tcti != NULL) {
        free(state.tcti);
    }
    if (state.encrypted_dir != NULL) {
        free(state.encrypted_dir);
    }
    return ret;
}
