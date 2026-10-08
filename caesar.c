// File caesar.c
// Date 28/09/2026
// Inspired by https://github.com/levitte/osslwebinar-provauthors-skeleton/,
// https://github.com/provider-corner/vigenere, 
// and https://github.com/tpm2-software/tpm2-openssl/

// Minimal dependencies (as per OpenSSL provider lecture)
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

// Printing, string comparison
#include <stdio.h>
#include <string.h>

//#include <openssl/params.h>
#include <openssl/core_names.h>

// OpenSSL compatible return codes
// TODO maybe they are included in some header already?
#define SUCCESS 1
#define FAILURE 0

// Modes for update function
#define ENCRYPT 0
#define DECRYPT 1

struct caesar_ctx {
    struct provider_ctx_st *provctx;
    unsigned char key;
    int mode;
};

// Hook the functions
// TODO: can this be merged with the function body? Probably not
static OSSL_FUNC_provider_gettable_params_fn gettable_params;
static OSSL_FUNC_provider_get_params_fn get_params;

// Hook query
static OSSL_FUNC_provider_query_operation_fn query; // to fetch algorithm implementation

// Caesar algorithm functions in provider format
// Needed to show up in the cipher list
// Contex management
static OSSL_FUNC_cipher_newctx_fn caesar_cipher_newctx;
static void *caesar_cipher_newctx(void *provctx)
{
    struct caesar_ctx *ctx = malloc(sizeof(*ctx));
    return ctx; 
}

static OSSL_FUNC_cipher_freectx_fn caesar_cipher_freectx;
static void caesar_cipher_freectx(void *cipherctx)
{ 
    free(cipherctx);
    cipherctx = NULL;
}

// Init
// TODO merge the common init steps into a function for both encrypt and decrypt
static OSSL_FUNC_cipher_encrypt_init_fn caesar_cipher_encrypt_init;
static int caesar_cipher_encrypt_init(void *cipherctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM *params)
{
    struct caesar_ctx *ctx = cipherctx;
    // TODO check for NULL
    ctx->key = key[0]; // uses first character as the key
    ctx->mode = ENCRYPT;
    return SUCCESS; 
}

static OSSL_FUNC_cipher_decrypt_init_fn caesar_cipher_decrypt_init;
static int caesar_cipher_decrypt_init(void *cipherctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM *params)
{
    struct caesar_ctx *ctx = cipherctx;
    // TODO check for NULL
    ctx->key = key[0]; // uses first character as the key
    ctx->mode = DECRYPT;
    return SUCCESS;
}

static OSSL_FUNC_cipher_update_fn caesar_cipher_update;
static int caesar_cipher_update(void *cipherctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl)
{ 
    struct caesar_ctx *ctx = cipherctx;
    if ((in == NULL) || (inl > outsize)){
        return FAILURE;
    }
    // TODO remove for loops
    if (ctx->mode == ENCRYPT){
        printf("ENCRYPT with key %c\n", ctx->key);
        for (int i = 0; i < inl; i++){
            out[i] = in[i] + ctx->key;
        }
    }
    else {
        printf("DECRYPT with key %c\n", ctx->key);
        for (int i = 0; i < inl; i++){
            out[i] = in[i] - ctx->key;
        }
    }
    *outl = inl;
    return SUCCESS;
}
static OSSL_FUNC_cipher_final_fn caesar_cipher_final;
static int caesar_cipher_final(void *cipherctx, unsigned char *out, size_t *outl,
                           size_t outsize)
{
    *outl = 0;
    return SUCCESS;
}

// TODO remove this
//static OSSL_FUNC_cipher_get_params_fn cesar_cipher_get_params;
static int caesar_cipher_get_params(OSSL_PARAM *params)
{
    for (; params != NULL && params->key != NULL; params++) {
        if ((strcasecmp(params->key, "blocksize") == 0) || (strcasecmp(params->key, "size") == 0)) {
            if (params->data_type == OSSL_PARAM_UNSIGNED_INTEGER
                && params->data_size == sizeof(size_t)) {
                size_t *r = params->data;
                *r = 1;
            } else {
                return 0;
            }
        }
    }
    return 1;
}

static OSSL_FUNC_cipher_get_params_fn cesar_get_params;
static int caesar_get_params(OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    if (params == NULL)
        return FAILURE; //?

    // TODO how exactly does this function work?
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return FAILURE;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return FAILURE;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
        return FAILURE;

    return SUCCESS;
}

// TODO check why is this function necessary and rewrite
static OSSL_FUNC_cipher_get_ctx_params_fn caesar_get_ctx_params;
static int caesar_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    return caesar_get_params(params);
}

static const OSSL_DISPATCH caesar_implementation[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))caesar_cipher_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))caesar_cipher_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))caesar_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))caesar_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))caesar_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))caesar_cipher_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))caesar_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))caesar_get_ctx_params },
    { 0, NULL }
};

// Provider functions
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)) gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*))get_params},
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*) (void)) query}, 
    {0, NULL} // TODO: is this end marker needed?
};

// Return provider parameter values for parameters queried by OpenSSL
// Only buildinfo implemented
static int get_params(void *provctx, OSSL_PARAM *params){
    // Check if OpenSSL wants build info
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    // If yes, return commit ID
    if (p != NULL){
        // to be configured at compile time: gcc -DCOMMITID=\"abcd1234\"
        if (!OSSL_PARAM_set_utf8_ptr(p, COMMITID))
        return FAILURE;
    }
    return SUCCESS;
}

// Return parameters that can be queried
static const OSSL_PARAM *gettable_params(void *provctx){
    static const OSSL_PARAM params[] = { 
        // (key, address, size)
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

// List of available ciphers
static const OSSL_ALGORITHM ciphers[] = {
    // fileds: name, properties, implementation, description
    {"CAESAR:id-caesar:1.0", "x.author=caesar", caesar_implementation, "Caesar implements the Caesar cipher."},
    {NULL, NULL, NULL, NULL}
};

// Return names, descriptions and implementations of operations of a given type (cipher, digest..)
static const OSSL_ALGORITHM *query(void *provctx, int operation_id, int *no_cache){
    *no_cache = 0; // not 0 ->results must not be cached => 0 -> can be cached
    switch(operation_id){
        case OSSL_OP_CIPHER:
            return ciphers;
    }
    return NULL;
}

// Initialize the provider
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, // handle object used by OpenSSL
                    const OSSL_DISPATCH *in, // functions provided by OpenSSL
                    const OSSL_DISPATCH **out, // functions offered by this provider
                    void **provctx) // provider context
{
    *out = provider_functions;
    return SUCCESS;
}

/* End of file caesar.c */
