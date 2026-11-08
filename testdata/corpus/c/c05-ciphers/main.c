#include <openssl/evp.h>

void ciphers(void) {
    const EVP_CIPHER *a = EVP_aes_256_gcm();
    const EVP_CIPHER *t = EVP_des_ede3_cbc();
    const EVP_CIPHER *c = EVP_chacha20_poly1305();
}
