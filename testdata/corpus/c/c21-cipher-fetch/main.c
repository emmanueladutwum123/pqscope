#include <openssl/evp.h>

void ciphers(void) {
    EVP_CIPHER *a = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    EVP_CIPHER *b = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", NULL);
}
