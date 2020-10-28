#ifndef AWS_C_CAL_OPENSSLCRYPTO_COMMON_H
#define AWS_C_CAL_OPENSSLCRYPTO_COMMON_H

#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef void (*hmac_ctx_init)(HMAC_CTX *);
typedef void (*hmac_ctx_clean_up)(HMAC_CTX *);

struct openssl_hmac_ctx_1_0_table {
    hmac_ctx_init init_fn;
    hmac_ctx_clean_up clean_up_fn;
};

typedef HMAC_CTX *(*hmac_ctx_new)(void);
typedef void (*hmac_ctx_reset)(HMAC_CTX *);
typedef void (*hmac_ctx_free)(HMAC_CTX *);

struct openssl_hmac_ctx_1_1_table {
    hmac_ctx_new new_fn;
    hmac_ctx_reset reset_fn;
    hmac_ctx_free free_fn;
};

typedef EVP_MD_CTX *(*evp_md_ctx_new)(void);
typedef void (*evp_md_ctx_free)(EVP_MD_CTX *);

struct openssl_evp_md_ctx_table {
    evp_md_ctx_new new_fn;
    evp_md_ctx_free free_fn;
};

extern struct openssl_hmac_ctx_1_0_table *g_aws_openssl_hmac_ctx_1_0_table;
extern struct openssl_hmac_ctx_1_1_table *g_aws_openssl_hmac_ctx_1_1_table;

extern struct openssl_evp_md_ctx_table *g_aws_openssl_evp_md_ctx_table;

#endif /* AWS_C_CAL_OPENSSLCRYPTO_COMMON_H */
