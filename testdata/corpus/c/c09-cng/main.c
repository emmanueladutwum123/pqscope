#include <windows.h>
#include <bcrypt.h>

void providers(void) {
    BCRYPT_ALG_HANDLE rsa, sha;
    BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, NULL, 0);
}
