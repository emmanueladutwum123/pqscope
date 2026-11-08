#include <openssl/evp.h>

EVP_PKEY *make(void) {
    return EVP_RSA_gen(3072);
}
