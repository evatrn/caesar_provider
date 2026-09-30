// File caesar.c
// Date 28/09/2026
// Inspired by https://github.com/levitte/osslwebinar-provauthors-skeleton/

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

// Hook the functions
// TODO: can this be merged with the function body?
static OSSL_FUNC_provider_gettable_params_fn gettable_params;
static OSSL_FUNC_provider_get_params_fn get_params;

// Hook query
static OSSL_FUNC_provider_query_operation_fn query; // to fetch algorithm implementation

// Caesar algorithm functions in provider format
// Needed to show in the cipher list
// Contex  management
static OSSL_FUNC_cipher_newctx_fn caesar_cipher_newctx;
static void *caesar_cipher_newctx(void *provctx) { return NULL; }
static OSSL_FUNC_cipher_freectx_fn caesar_cipher_freectx;
static void caesar_cipher_freectx(void *cipherctx) { }
// Init
static OSSL_FUNC_cipher_encrypt_init_fn caesar_cipher_encrypt_init;
static int caesar_cipher_encrypt_init(void *cipherctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM *params) { return 0; }
static OSSL_FUNC_cipher_decrypt_init_fn caesar_cipher_decrypt_init;
static int caesar_cipher_decrypt_init(void *cipherctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM *params) { return 0; }

static OSSL_FUNC_cipher_update_fn caesar_cipher_update;
static int caesar_cipher_update(void *cipherctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl) { return 0; }
static OSSL_FUNC_cipher_final_fn caesar_cipher_final;
static int caesar_cipher_final(void *cipherctx, unsigned char *out, size_t *outl,
                           size_t outsize) { return 0; }

static OSSL_FUNC_cipher_cipher_fn caesar_cipher_cipher;
static int caesar_cipher_cipher(void *cipherctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl) { return 0; }

// TODO parameters should reflect real needs of blockcipher (iv, key...)
static OSSL_FUNC_cipher_get_params_fn cesar_cipher_get_params;
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

// Provider functions
static const OSSL_DISPATCH provider_functions[] = { 
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)) gettable_params } ,
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

// CAESAR !!
static const OSSL_DISPATCH caesar_implementation[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))caesar_cipher_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))caesar_cipher_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))caesar_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))caesar_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))caesar_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))caesar_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))caesar_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))caesar_cipher_get_params },
    { 0, NULL }
};


// List of available ciphers
static const OSSL_ALGORITHM ciphers[] ={
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
