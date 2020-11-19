/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>

#include <dlfcn.h>

#include <aws/cal/private/opensslcrypto_common.h>

static struct openssl_hmac_ctx_table hmac_ctx_table;
static struct openssl_evp_md_ctx_table evp_md_ctx_table;

struct openssl_hmac_ctx_table *g_aws_openssl_hmac_ctx_table = NULL;
struct openssl_evp_md_ctx_table *g_aws_openssl_evp_md_ctx_table = NULL;

/* weak refs to libcrypto functions to force them to at least try to link
 * and avoid dead-stripping
 */
/* 1.1 */
extern HMAC_CTX *HMAC_CTX_new(void) __attribute__((weak)) __attribute__((used));
extern void HMAC_CTX_free(HMAC_CTX *) __attribute__((weak)) __attribute__((used));
extern int HMAC_CTX_reset(HMAC_CTX *) __attribute__((weak)) __attribute__((used));

/* 1.0.2 */
extern void HMAC_CTX_init(HMAC_CTX *) __attribute__((weak)) __attribute__((used));
extern void HMAC_CTX_cleanup(HMAC_CTX *) __attribute__((weak)) __attribute__((used));

/* common */
extern int HMAC_Update(HMAC_CTX *, const unsigned char *, size_t) __attribute__((weak)) __attribute__((used));
extern int HMAC_Final(HMAC_CTX *, unsigned char *, unsigned int *) __attribute__((weak)) __attribute__((used));
extern int HMAC_Init_ex(HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *) __attribute__((weak))
__attribute__((used));

/* EVP_MD_CTX API */
/* 1.0.2 NOTE: these are macros in 1.1.x, so we only use them as functions when
 * runtime resolving against libcrypto 1.0.2 .so, we only link against 1.1.1 */
/*extern EVP_MD_CTX *EVP_MD_CTX_create(void) __attribute__((weak)) __attribute__((used));*/
/*extern void EVP_MD_CTX_destroy(EVP_MD_CTX *) __attribute__((weak)) __attribute__((used));*/

/* 1.1 */
extern EVP_MD_CTX *EVP_MD_CTX_new(void) __attribute__((weak)) __attribute__((used));
extern void EVP_MD_CTX_free(EVP_MD_CTX *) __attribute__((weak)) __attribute__((used));

/* common */
extern int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *) __attribute__((weak)) __attribute__((used));
extern int EVP_DigestUpdate(EVP_MD_CTX *, const void *, size_t) __attribute__((weak)) __attribute__((used));
extern int EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *) __attribute__((weak))
__attribute__((used));

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

/* libcrypto 1.0 shim for reset, matches HMAC_CTX_reset semantics */
static int s_hmac_ctx_reset(HMAC_CTX *ctx) {
    AWS_PRECONDITION(ctx);
    AWS_PRECONDITION(
        g_aws_openssl_hmac_ctx_table->init_fn != s_hmac_ctx_init_noop &&
        g_aws_openssl_hmac_ctx_table->clean_up_fn != s_hmac_ctx_clean_up_noop &&
        "libcrypto 1.0 reset called on libcrypto 1.1 vtable");
    g_aws_openssl_hmac_ctx_table->clean_up_fn(ctx);
    g_aws_openssl_hmac_ctx_table->init_fn(ctx);
    return 1;
}

static struct aws_mutex *s_libcrypto_locks = NULL;
static struct aws_allocator *s_libcrypto_allocator = NULL;

static void s_locking_fn(int mode, int n, const char *unused0, int unused1) {
    (void)unused0;
    (void)unused1;

    if (mode & CRYPTO_LOCK) {
        aws_mutex_lock(&s_libcrypto_locks[n]);
    } else {
        aws_mutex_unlock(&s_libcrypto_locks[n]);
    }
}

static unsigned long s_id_fn(void) {
    return (unsigned long)aws_thread_current_thread_id();
}

enum aws_libcrypto_version {
    AWS_LIBCRYPTO_NONE,
    AWS_LIBCRYPTO_102,
    AWS_LIBCRYPTO_111,
    AWS_LIBCRYPTO_LC,
} s_libcrypto_version = AWS_LIBCRYPTO_NONE;

void *s_find_libcrypto_module(void) {
#if defined(AWS_CAL_EXPORTS)
    const char *libcrypto_110 = "libcrypto.so.1.1";
    const char *libcrypto_102 = "libcrypto.so.1.0.0";
    void *module = dlopen(libcrypto_102, RTLD_NOW);
    if (module) {
        s_libcrypto_version = AWS_LIBCRYPTO_102;
        return module;
    }
    module = dlopen(libcrypto_110, RTLD_NOW);
    if (module) {
        s_libcrypto_version = AWS_LIBCRYPTO_111;
        return module;
    }
#endif
    return dlopen(NULL, RTLD_NOW);
}

void aws_cal_platform_init(struct aws_allocator *allocator) {
    s_libcrypto_allocator = allocator;

    void *this_handle = s_find_libcrypto_module();
    AWS_FATAL_ASSERT(this_handle != NULL);

    {
        hmac_ctx_init init_fn = HMAC_CTX_init;
        hmac_ctx_clean_up clean_up_fn = HMAC_CTX_cleanup;
        hmac_ctx_new new_fn = HMAC_CTX_new;
        hmac_ctx_free free_fn = HMAC_CTX_free;
        hmac_ctx_reset reset_fn = HMAC_CTX_reset;
        hmac_ctx_update update_fn = HMAC_Update;
        hmac_ctx_final final_fn = HMAC_Final;
        hmac_ctx_init_ex init_ex_fn = HMAC_Init_ex;

        if (!init_fn) {
            *(void **)(&init_fn) = dlsym(this_handle, "HMAC_CTX_init");
        }
        if (!clean_up_fn) {
            *(void **)(&clean_up_fn) = dlsym(this_handle, "HMAC_CTX_cleanup");
        }

        if (init_fn && clean_up_fn) {
            s_libcrypto_version = AWS_LIBCRYPTO_102;
        }

        if (s_libcrypto_version != AWS_LIBCRYPTO_102) {
            if (!new_fn) {
                *(void **)(&new_fn) = dlsym(this_handle, "HMAC_CTX_new");
            }
            if (!reset_fn) {
                *(void **)(&reset_fn) = dlsym(this_handle, "HMAC_CTX_reset");
            }
            if (!free_fn) {
                *(void **)(&free_fn) = dlsym(this_handle, "HMAC_CTX_free");
            }
            if (new_fn && reset_fn && free_fn) {
                s_libcrypto_version = AWS_LIBCRYPTO_111;
            }
        }

        AWS_FATAL_ASSERT(s_libcrypto_version != AWS_LIBCRYPTO_NONE);

        if (!update_fn) {
            *(void **)(&update_fn) = dlsym(this_handle, "HMAC_Update");
        }
        if (!final_fn) {
            *(void **)(&final_fn) = dlsym(this_handle, "HMAC_Final");
        }
        if (!init_ex_fn) {
            *(void **)(&init_ex_fn) = dlsym(this_handle, "HMAC_Init_ex");
        }

        AWS_FATAL_ASSERT(update_fn != NULL && "libcrypto HMAC_Update could not be resolved");
        AWS_FATAL_ASSERT(final_fn != NULL && "libcrypto HMAC_Final could not be resolved");
        AWS_FATAL_ASSERT(init_ex_fn != NULL && "libcrypto HMAC_Init_ex could not be resolved");

        hmac_ctx_table.update_fn = update_fn;
        hmac_ctx_table.final_fn = final_fn;
        hmac_ctx_table.init_ex_fn = init_ex_fn;

        if (new_fn != NULL && reset_fn != NULL && free_fn != NULL) {
            /* libcrypto 1.1 */
            hmac_ctx_table.new_fn = new_fn;
            hmac_ctx_table.reset_fn = reset_fn;
            hmac_ctx_table.free_fn = free_fn;
            hmac_ctx_table.init_fn = s_hmac_ctx_init_noop;
            hmac_ctx_table.clean_up_fn = s_hmac_ctx_clean_up_noop;
            g_aws_openssl_hmac_ctx_table = &hmac_ctx_table;

        } else if (init_fn != NULL && clean_up_fn != NULL) {
            /* libcrypto 1.0 */
            hmac_ctx_table.new_fn = s_hmac_ctx_new;
            hmac_ctx_table.reset_fn = s_hmac_ctx_reset;
            hmac_ctx_table.free_fn = s_hmac_ctx_free;
            hmac_ctx_table.init_fn = init_fn;
            hmac_ctx_table.clean_up_fn = clean_up_fn;
            g_aws_openssl_hmac_ctx_table = &hmac_ctx_table;
        }

        AWS_FATAL_ASSERT(g_aws_openssl_hmac_ctx_table != NULL);
    }

    /* OpenSSL changed the EVP api in 1.1 to use new/free verbs */
    {
        evp_md_ctx_new md_new_fn = EVP_MD_CTX_new;
        if (!md_new_fn) {
            *(void **)(&md_new_fn) = dlsym(this_handle, "EVP_MD_CTX_new");
            if (md_new_fn == NULL) {
                *(void **)(&md_new_fn) = dlsym(this_handle, "EVP_MD_CTX_create");
            }
        }
        AWS_FATAL_ASSERT(md_new_fn != NULL);
        evp_md_ctx_table.new_fn = md_new_fn;

        evp_md_ctx_free md_free_fn = EVP_MD_CTX_free;
        if (!md_free_fn) {
            *(void **)(&md_free_fn) = dlsym(this_handle, "EVP_MD_CTX_free");
            if (md_free_fn == NULL) {
                *(void **)(&md_free_fn) = dlsym(this_handle, "EVP_MD_CTX_destroy");
            }
        }
        AWS_FATAL_ASSERT(md_free_fn != NULL);
        evp_md_ctx_table.free_fn = md_free_fn;

        evp_md_ctx_digest_init_ex md_init_ex_fn = EVP_DigestInit_ex;
        if (!md_init_ex_fn) {
            *(void **)(&md_init_ex_fn) = dlsym(this_handle, "EVP_DigestInit_ex");
        }
        AWS_FATAL_ASSERT(md_init_ex_fn != NULL);
        evp_md_ctx_table.init_ex_fn = md_init_ex_fn;

        evp_md_ctx_digest_update md_update_fn = EVP_DigestUpdate;
        if (!md_update_fn) {
            *(void **)(&md_update_fn) = dlsym(this_handle, "EVP_DigestUpdate");
        }
        AWS_FATAL_ASSERT(md_update_fn);
        evp_md_ctx_table.update_fn = md_update_fn;

        evp_md_ctx_digest_final_ex md_final_ex_fn = EVP_DigestFinal_ex;
        if (!md_final_ex_fn) {
            *(void **)(&md_final_ex_fn) = dlsym(this_handle, "EVP_DigestFinal_ex");
        }
        AWS_FATAL_ASSERT(md_final_ex_fn);
        evp_md_ctx_table.final_ex_fn = md_final_ex_fn;

        g_aws_openssl_evp_md_ctx_table = &evp_md_ctx_table;
        AWS_FATAL_ASSERT(g_aws_openssl_evp_md_ctx_table != NULL);
    }

    dlclose(this_handle);

    /* Ensure that libcrypto 1.0.2 has working locking mechanisms. This code is macro'ed
     * by libcrypto to be a no-op on 1.1.1 */
    if (!CRYPTO_get_locking_callback()) {
        s_libcrypto_locks = aws_mem_acquire(allocator, sizeof(struct aws_mutex) * CRYPTO_num_locks());
        AWS_FATAL_ASSERT(s_libcrypto_locks);
        size_t lock_count = (size_t)CRYPTO_num_locks();
        for (size_t i = 0; i < lock_count; ++i) {
            aws_mutex_init(&s_libcrypto_locks[i]);
        }
        CRYPTO_set_locking_callback(s_locking_fn);
    }

    if (!CRYPTO_get_id_callback()) {
        CRYPTO_set_id_callback(s_id_fn);
    }
}

/* Ignore warnings about how CRYPTO_get_locking_callback() always returns NULL on 1.1.1 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
void aws_cal_platform_clean_up(void) {
    if (CRYPTO_get_locking_callback() == s_locking_fn) {
        CRYPTO_set_locking_callback(NULL);
        size_t lock_count = (size_t)CRYPTO_num_locks();
        for (size_t i = 0; i < lock_count; ++i) {
            aws_mutex_clean_up(&s_libcrypto_locks[i]);
        }
        aws_mem_release(s_libcrypto_allocator, s_libcrypto_locks);
    }

    if (CRYPTO_get_id_callback() == s_id_fn) {
        CRYPTO_set_id_callback(NULL);
    }
}
#pragma GCC diagnostic pop
