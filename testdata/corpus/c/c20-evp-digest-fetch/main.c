#include <openssl/evp.h>

void digests(void) {
    EVP_MD *a = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    const EVP_MD *b = EVP_get_digestbyname("MD5");
}
