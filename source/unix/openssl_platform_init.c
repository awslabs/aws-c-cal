/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>

#include <dlfcn.h>

#include <aws/cal/private/opensslcrypto_common.h>

#if defined(AWS_LIBCRYPTO_LOG_RESOLVE)
#    define FLOGF(...)                                                                                                 \
        do {                                                                                                           \
            fprintf(stderr, "AWS libcrypto resolve: ");                                                                \
            fprintf(stderr, __VA_ARGS__);                                                                              \
            fprintf(stderr, "\n");                                                                                     \
        } while (0)
#else
#    define FLOGF(...)
#endif

static struct openssl_hmac_ctx_table hmac_ctx_table;
static struct openssl_evp_md_ctx_table evp_md_ctx_table;

struct openssl_hmac_ctx_table *g_aws_openssl_hmac_ctx_table = NULL;
struct openssl_evp_md_ctx_table *g_aws_openssl_evp_md_ctx_table = NULL;

/* weak refs to libcrypto functions to force them to at least try to link
 * and avoid dead-stripping
 */
extern HMAC_CTX *HMAC_CTX_new(void) __attribute__((weak)) __attribute__((used));
extern void HMAC_CTX_free(HMAC_CTX *) __attribute__((weak)) __attribute__((used));
extern void HMAC_CTX_reset(HMAC_CTX *) __attribute__((weak)) __attribute__((used));
extern void HMAC_CTX_init(HMAC_CTX *) __attribute__((weak)) __attribute__((used));
extern void HMAC_CTX_cleanup(HMAC_CTX *) __attribute__((weak)) __attribute__((used));
extern int HMAC_Update(HMAC_CTX *, const unsigned char *, size_t) __attribute__((weak)) __attribute__((used));
extern int HMAC_Final(HMAC_CTX *, unsigned char *, unsigned int *) __attribute__((weak)) __attribute__((used));
extern int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *) __attribute__((weak))
__attribute__((used));

enum aws_libcrypto_version {
    AWS_LIBCRYPTO_NONE = 0,
    AWS_LIBCRYPTO_LC,
} s_libcrypto_version = AWS_LIBCRYPTO_NONE;

static int s_resolve_libcrypto_hmac(enum aws_libcrypto_version version, void *module) {
    hmac_ctx_init init_fn = HMAC_CTX_init;
    hmac_ctx_clean_up clean_up_fn = HMAC_CTX_cleanup;
    hmac_ctx_new new_fn = HMAC_CTX_new;
    hmac_ctx_free free_fn = HMAC_CTX_free;
    hmac_ctx_reset reset_fn = HMAC_CTX_reset;
    hmac_ctx_update update_fn = HMAC_Update;
    hmac_ctx_final final_fn = HMAC_Final;
    hmac_ctx_init_ex init_ex_fn = HMAC_Init_ex;

    /* were symbols bound by static linking? */
    bool has_awslc_symbols = new_fn && free_fn && update_fn && final_fn && init_fn && init_ex_fn && reset_fn;

    /* If symbols aren't already found, try to find the requested version */
    /* when built as a shared lib, and multiple versions of libcrypto are possibly
     * available (e.g. brazil), select AWS-LC by default for consistency */
    if (!has_awslc_symbols && version == AWS_LIBCRYPTO_LC) {
        *(void **)(&new_fn) = dlsym(module, "HMAC_CTX_new");
        *(void **)(&reset_fn) = dlsym(module, "HMAC_CTX_reset");
        *(void **)(&free_fn) = dlsym(module, "HMAC_CTX_free");
        *(void **)(&update_fn) = dlsym(module, "HMAC_Update");
        *(void **)(&final_fn) = dlsym(module, "HMAC_Final");
        *(void **)(&init_ex_fn) = dlsym(module, "HMAC_Init_ex");
        if (new_fn) {
            FLOGF("found dynamic aws-lc HMAC symbols");
        }
    }

    /* Fill out the vtable for the requested version */
    hmac_ctx_table.new_fn = new_fn;
    hmac_ctx_table.reset_fn = reset_fn;
    hmac_ctx_table.free_fn = free_fn;
    hmac_ctx_table.init_fn = init_fn;
    hmac_ctx_table.clean_up_fn = clean_up_fn;
    hmac_ctx_table.update_fn = update_fn;
    hmac_ctx_table.final_fn = final_fn;
    hmac_ctx_table.init_ex_fn = init_ex_fn;
    g_aws_openssl_hmac_ctx_table = &hmac_ctx_table;

    return version;
}

extern EVP_MD_CTX *EVP_MD_CTX_new(void) __attribute__((weak, used));
extern void EVP_MD_CTX_free(EVP_MD_CTX *) __attribute__((weak, used));
extern int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *) __attribute__((weak, used));
extern int EVP_DigestUpdate(EVP_MD_CTX *, const void *, size_t) __attribute__((weak, used));
extern int EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *) __attribute__((weak, used));

static int s_resolve_libcrypto_md(enum aws_libcrypto_version version, void *module) {
    evp_md_ctx_new md_new_fn = EVP_MD_CTX_new;
    evp_md_ctx_new md_create_fn = EVP_MD_CTX_new;
    evp_md_ctx_free md_free_fn = EVP_MD_CTX_free;
    evp_md_ctx_free md_destroy_fn = EVP_MD_CTX_destroy;
    evp_md_ctx_digest_init_ex md_init_ex_fn = EVP_DigestInit_ex;
    evp_md_ctx_digest_update md_update_fn = EVP_DigestUpdate;
    evp_md_ctx_digest_final_ex md_final_ex_fn = EVP_DigestFinal_ex;

    bool has_awslc_symbols =
        md_new_fn && md_create_fn && md_free_fn && md_destroy_fn && md_init_ex_fn && md_update_fn && md_final_ex_fn;

    if (!has_awslc_symbols && version == AWS_LIBCRYPTO_LC) {
        *(void **)(&md_new_fn) = dlsym(module, "EVP_MD_CTX_new");
        *(void **)(&md_free_fn) = dlsym(module, "EVP_MD_CTX_free");
        *(void **)(&md_init_ex_fn) = dlsym(module, "EVP_DigestInit_ex");
        *(void **)(&md_update_fn) = dlsym(module, "EVP_DigestUpdate");
        *(void **)(&md_final_ex_fn) = dlsym(module, "EVP_DigestFinal_ex");
        if (md_new_fn) {
            FLOGF("found dynamic libcrypto 1.1.1 EVP_MD symbols");
        }
    }

    /* Add the found symbols to the vtable */
    evp_md_ctx_table.new_fn = md_new_fn;
    evp_md_ctx_table.free_fn = md_free_fn;
    evp_md_ctx_table.init_ex_fn = md_init_ex_fn;
    evp_md_ctx_table.update_fn = md_update_fn;
    evp_md_ctx_table.final_ex_fn = md_final_ex_fn;
    g_aws_openssl_evp_md_ctx_table = &evp_md_ctx_table;

    return version;
}

static int s_resolve_libcrypto_symbols(enum aws_libcrypto_version version, void *module) {
    int found_version = s_resolve_libcrypto_hmac(version, module);
    if (!found_version) {
        return AWS_LIBCRYPTO_NONE;
    }
    if (!s_resolve_libcrypto_md(found_version, module)) {
        return AWS_LIBCRYPTO_NONE;
    }
    return found_version;
}

static int s_resolve_libcrypto(void) {
    if (s_libcrypto_version != AWS_LIBCRYPTO_NONE) {
        return s_libcrypto_version;
    }

    /* Try to auto-resolve against what's linked in/process space */
    FLOGF("searching process and loaded modules");
    void *process = dlopen(NULL, RTLD_NOW);
    AWS_FATAL_ASSERT(process && "Unable to load symbols from process space");
    int result = s_resolve_libcrypto_symbols(AWS_LIBCRYPTO_LC, process);
    dlclose(process);

    return result;
}

/* Ignore warnings about how CRYPTO_get_locking_callback() always returns NULL on 1.1.1 */
#if !defined(__GNUC__) || (__GNUC__ >= 4 && __GNUC_MINOR__ > 1)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Waddress"
#endif

void aws_cal_platform_init(struct aws_allocator *allocator) {
    int version = s_resolve_libcrypto();
    AWS_FATAL_ASSERT(version != AWS_LIBCRYPTO_NONE && "libcrypto could not be resolved");
}

void aws_cal_platform_clean_up(void) {}
#if !defined(__GNUC__) || (__GNUC__ >= 4 && __GNUC_MINOR__ > 1)
#    pragma GCC diagnostic pop
#endif
