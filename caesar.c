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


static const OSSL_DISPATCH caesar_functions[] = { { 0, NULL } };

static int caesar_get_params(void *provctx, OSSL_PARAM *params){
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

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, // handle object used by OpenSSL
                    const OSSL_DISPATCH *in, // functions provided by OpenSSL
                    const OSSL_DISPATCH **out, // functions offered by this provider
                    void **provctx) // provider context
{
    *out = caesar_functions;
    return SUCCESS;
}

/* End of file caesar.c */
