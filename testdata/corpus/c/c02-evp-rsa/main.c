#include <openssl/evp.h>
#include <openssl/rsa.h>

EVP_PKEY_CTX *make(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    return ctx;
}
