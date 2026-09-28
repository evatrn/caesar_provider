// File caesar.c
// Date 28/09/2026

// Minimal dependencies (as per OpenSSL provider lecture)
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

static const OSSL_DISPATCH caesar_functions[] = { { 0, NULL } };

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, // used by OpenSSL
                    const OSSL_DISPATCH *in, // functions provided by OpenSSL
                    const OSSL_DISPATCH **out, // functions offered by this provider
                    void **provctx) // provider context
{
    *out = caesar_functions;
    return 1; // SUCCESS
}


