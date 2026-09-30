// File caesar.c
// Date 28/09/2026

// Minimal dependencies (as per OpenSSL provider lecture)
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

//#include <openssl/params.h>
#include <openssl/core_names.h>

// OpenSSL compatible return codes
#define SUCCESS 1
#define FAILURE 0

// Hook the functions
// TODO: can this be merged with the function body?
static OSSL_FUNC_provider_gettable_params_fn gettable_params;
static OSSL_FUNC_provider_get_params_fn get_params;

// Provider functions
static const OSSL_DISPATCH provider_functions[] = { 
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)) gettable_params } ,
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*))get_params},
    {0, NULL} // TODO: is this an end marker?
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
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, // handle object used by OpenSSL
                    const OSSL_DISPATCH *in, // functions provided by OpenSSL
                    const OSSL_DISPATCH **out, // functions offered by this provider
                    void **provctx) // provider context
{
    *out = provider_functions;
    return SUCCESS;
}

/* End of file caesar.c */
