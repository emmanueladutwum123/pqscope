#include <openssl/evp.h>

static EVP_PKEY *gen(unsigned int bits) {
    return EVP_RSA_gen(bits);
}

EVP_PKEY *make(void) { return gen(2048); }
