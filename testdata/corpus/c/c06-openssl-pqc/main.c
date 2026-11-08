#include <openssl/evp.h>

void pqc(void) {
    EVP_PKEY_CTX *k = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    EVP_PKEY *s = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
}
