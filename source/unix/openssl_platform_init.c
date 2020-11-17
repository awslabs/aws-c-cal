/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>

#include <dlfcn.h>

#include <aws/cal/private/opensslcrypto_common.h>

static struct openssl_hmac_ctx_table hmac_ctx_table;
static struct openssl_evp_md_ctx_table evp_md_ctx_table;

struct openssl_hmac_ctx_table *g_aws_openssl_hmac_ctx_table = NULL;
struct openssl_evp_md_ctx_table *g_aws_openssl_evp_md_ctx_table = NULL;

/* libcrypto 1.1 stub for init */
static void s_hmac_ctx_init_noop(HMAC_CTX *ctx) {
    (void)ctx;
}

/* libcrypto 1.1 stub for clean_up */
static void s_hmac_ctx_clean_up_noop(HMAC_CTX *ctx) {
    (void)ctx;
}

/* libcrypto 1.0 shim for new */
static HMAC_CTX *s_hmac_ctx_new(void) {
    AWS_PRECONDITION(
        g_aws_openssl_hmac_ctx_table->init_fn != s_hmac_ctx_init_noop &&
        "libcrypto 1.0 init called on libcrypto 1.1 vtable");
    HMAC_CTX *ctx = aws_mem_calloc(aws_default_allocator(), 1, 300);
    AWS_FATAL_ASSERT(ctx && "Unable to allocate to HMAC_CTX");
    g_aws_openssl_hmac_ctx_table->init_fn(ctx);
    return ctx;
}

/* libcrypto 1.0 shim for free */
static void s_hmac_ctx_free(HMAC_CTX *ctx) {
    AWS_PRECONDITION(ctx);
    AWS_PRECONDITION(
        g_aws_openssl_hmac_ctx_table->clean_up_fn != s_hmac_ctx_clean_up_noop &&
        "libcrypto 1.0 clean_up called on libcrypto 1.1 vtable");
    g_aws_openssl_hmac_ctx_table->clean_up_fn(ctx);
    aws_mem_release(aws_default_allocator(), ctx);
}

/* libcrypto 1.0 shim for reset */
static void s_hmac_ctx_reset(HMAC_CTX *ctx) {
    AWS_PRECONDITION(ctx);
    AWS_PRECONDITION(
        g_aws_openssl_hmac_ctx_table->init_fn != s_hmac_ctx_init_noop &&
        g_aws_openssl_hmac_ctx_table->clean_up_fn != s_hmac_ctx_clean_up_noop &&
        "libcrypto 1.0 reset called on libcrypto 1.1 vtable");
    g_aws_openssl_hmac_ctx_table->clean_up_fn(ctx);
    g_aws_openssl_hmac_ctx_table->init_fn(ctx);
}

void *s_find_libcrypto_module(void) {
#if defined(AWS_CAL_EXPORTS)
    const char *libcrypto_110 = "libcrypto.so.1.1";
    const char *libcrypto_102 = "libcrypto.so.1.0.0";
    void *module = dlopen(libcrypto_110, RTLD_NOW);
    if (module) {
        fprintf(stderr, "Found libcrypto.so.1.1\n");
        return module;
    }
    module = dlopen(libcrypto_102, RTLD_NOW);
    if (module) {
        fprintf(stderr, "Found libcrypto.so.1.0.0\n");
        return module;
    }
#endif
    fprintf(stderr, "Searching process space for libcrypto symbols\n");
    return dlopen(NULL, RTLD_NOW);
}

void aws_cal_platform_init(struct aws_allocator *allocator) {
    (void)allocator;

    void *this_handle = s_find_libcrypto_module();
    AWS_FATAL_ASSERT(this_handle != NULL);

    hmac_ctx_init init_fn = NULL;
    hmac_ctx_clean_up clean_up_fn = NULL;
    hmac_ctx_new new_fn = NULL;
    hmac_ctx_reset reset_fn = NULL;
    hmac_ctx_free free_fn = NULL;
    hmac_ctx_update update_fn = NULL;
    hmac_ctx_final final_fn = NULL;
    hmac_ctx_init_ex init_ex_fn = NULL;

    *(void **)(&init_fn) = dlsym(this_handle, "HMAC_CTX_init");
    *(void **)(&clean_up_fn) = dlsym(this_handle, "HMAC_CTX_cleanup");
    *(void **)(&new_fn) = dlsym(this_handle, "HMAC_CTX_new");
    *(void **)(&reset_fn) = dlsym(this_handle, "HMAC_CTX_reset");
    *(void **)(&free_fn) = dlsym(this_handle, "HMAC_CTX_free");
    *(void **)(&update_fn) = dlsym(this_handle, "HMAC_Update");
    *(void **)(&final_fn) = dlsym(this_handle, "HMAC_Final");
    *(void **)(&init_ex_fn) = dlsym(this_handle, "HMAC_Init_ex");

    AWS_FATAL_ASSERT(update_fn != NULL && "libcrypto HMAC_Update could not be resolved");
    AWS_FATAL_ASSERT(final_fn != NULL && "libcrypto HMAC_Final could not be resolved");
    AWS_FATAL_ASSERT(init_ex_fn != NULL && "libcrypto HMAC_Init_ex could not be resolved");

    hmac_ctx_table.update_fn = update_fn;
    hmac_ctx_table.final_fn = final_fn;
    hmac_ctx_table.init_ex_fn = init_ex_fn;

    if (new_fn != NULL && reset_fn != NULL && free_fn != NULL) {
        /* libcrypto 1.1 */
        fprintf(stderr, "Found libcrypto 1.1 symbols\n");
        hmac_ctx_table.new_fn = new_fn;
        hmac_ctx_table.reset_fn = reset_fn;
        hmac_ctx_table.free_fn = free_fn;
        hmac_ctx_table.init_fn = s_hmac_ctx_init_noop;
        hmac_ctx_table.clean_up_fn = s_hmac_ctx_clean_up_noop;
        g_aws_openssl_hmac_ctx_table = &hmac_ctx_table;

    } else if (init_fn != NULL && clean_up_fn != NULL) {
        /* libcrypto 1.0 */
        fprintf(stderr, "Found libcrypto 1.0.2 symbols\n");
        hmac_ctx_table.new_fn = s_hmac_ctx_new;
        hmac_ctx_table.reset_fn = s_hmac_ctx_reset;
        hmac_ctx_table.free_fn = s_hmac_ctx_free;
        hmac_ctx_table.init_fn = init_fn;
        hmac_ctx_table.clean_up_fn = clean_up_fn;
        g_aws_openssl_hmac_ctx_table = &hmac_ctx_table;
    }

    /* OpenSSL changed the EVP api in 1.1 to use new/free verbs */
    evp_md_ctx_new md_new_fn = NULL;
    *(void **)(&md_new_fn) = dlsym(this_handle, "EVP_MD_CTX_new");
    if (md_new_fn == NULL) {
        *(void **)(&md_new_fn) = dlsym(this_handle, "EVP_MD_CTX_create");
    }
    AWS_FATAL_ASSERT(md_new_fn != NULL);
    evp_md_ctx_table.new_fn = md_new_fn;

    evp_md_ctx_free md_free_fn = NULL;
    *(void **)(&md_free_fn) = dlsym(this_handle, "EVP_MD_CTX_free");
    if (md_free_fn == NULL) {
        *(void **)(&md_free_fn) = dlsym(this_handle, "EVP_MD_CTX_destroy");
    }
    AWS_FATAL_ASSERT(md_free_fn != NULL);
    evp_md_ctx_table.free_fn = md_free_fn;

    g_aws_openssl_evp_md_ctx_table = &evp_md_ctx_table;

    dlclose(this_handle);

    AWS_FATAL_ASSERT(g_aws_openssl_hmac_ctx_table != NULL);
    AWS_FATAL_ASSERT(g_aws_openssl_evp_md_ctx_table != NULL);
}
