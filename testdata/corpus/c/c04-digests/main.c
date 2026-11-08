#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

void digest(const unsigned char *in, size_t n, unsigned char *out) {
    const EVP_MD *md = EVP_sha256();
    SHA1(in, n, out);
    MD5(in, n, out);
}
