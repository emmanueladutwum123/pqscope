#include <windows.h>
#include <bcrypt.h>

void providers(void) {
    BCRYPT_ALG_HANDLE kem, ec;
    BCryptOpenAlgorithmProvider(&kem, BCRYPT_MLKEM_ALGORITHM, NULL, 0);
    BCryptOpenAlgorithmProvider(&ec, BCRYPT_ECDSA_P384_ALGORITHM, NULL, 0);
}
