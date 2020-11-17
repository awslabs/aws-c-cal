/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>

#include <dlfcn.h>

#include <aws/cal/private/opensslcrypto_common.h>

static struct openssl_hmac_ctx_1_0_table hmac_ctx_1_0_table;
static struct openssl_hmac_ctx_1_1_table hmac_ctx_1_1_table;
static struct openssl_evp_md_ctx_table evp_md_ctx_table;

struct openssl_hmac_ctx_1_0_table *g_aws_openssl_hmac_ctx_1_0_table = NULL;
struct openssl_hmac_ctx_1_1_table *g_aws_openssl_hmac_ctx_1_1_table = NULL;
struct openssl_evp_md_ctx_table *g_aws_openssl_evp_md_ctx_table = NULL;

void aws_cal_platform_init(struct aws_allocator *allocator) {
    (void)allocator;

    void *this_handle = dlopen(NULL, RTLD_NOW);
    AWS_FATAL_ASSERT(this_handle != NULL);

    hmac_ctx_init init_fn = NULL;
    hmac_ctx_clean_up clean_up_fn = NULL;
    hmac_ctx_new new_fn = NULL;
    hmac_ctx_reset reset_fn = NULL;
    hmac_ctx_free free_fn = NULL;

    *(void **)(&init_fn) = dlsym(this_handle, "HMAC_CTX_init");
    *(void **)(&clean_up_fn) = dlsym(this_handle, "HMAC_CTX_cleanup");
    *(void **)(&new_fn) = dlsym(this_handle, "HMAC_CTX_new");
    *(void **)(&reset_fn) = dlsym(this_handle, "HMAC_CTX_reset");
    *(void **)(&free_fn) = dlsym(this_handle, "HMAC_CTX_free");

    if (new_fn != NULL && reset_fn != NULL && free_fn != NULL) {
        fprintf(stderr, "FOUND OpenSSL-1.1, using new/reset/free API");
        hmac_ctx_1_1_table.new_fn = new_fn;
        hmac_ctx_1_1_table.reset_fn = reset_fn;
        hmac_ctx_1_1_table.free_fn = free_fn;
        g_aws_openssl_hmac_ctx_1_1_table = &hmac_ctx_1_1_table;

    } else if (init_fn != NULL && clean_up_fn != NULL) {
        hmac_ctx_1_0_table.init_fn = init_fn;
        hmac_ctx_1_0_table.clean_up_fn = clean_up_fn;
        g_aws_openssl_hmac_ctx_1_0_table = &hmac_ctx_1_0_table;
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

    AWS_FATAL_ASSERT(g_aws_openssl_hmac_ctx_1_0_table != NULL || g_aws_openssl_hmac_ctx_1_1_table != NULL);
    AWS_FATAL_ASSERT(g_aws_openssl_evp_md_ctx_table != NULL);
}
