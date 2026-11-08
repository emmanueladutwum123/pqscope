#include <openssl/rsa.h>

#define KEY_BITS 4096

int make(RSA *rsa, BIGNUM *e) {
    return RSA_generate_key_ex(rsa, KEY_BITS, e, NULL);
}
