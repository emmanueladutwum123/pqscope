#include <openssl/evp.h>

const EVP_MD *pick(void) {
    const EVP_MD *(*md)(void) = EVP_sha1;
    return md();
}
