#include <openssl/rsa.h>

int make(RSA *rsa, BIGNUM *e) {
    int bits = 4096;
    return RSA_generate_key_ex(rsa, bits, e, NULL);
}
