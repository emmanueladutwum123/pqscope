#include <sodium.h>

void keys(unsigned char *pk, unsigned char *sk) {
    crypto_box_keypair(pk, sk);
    crypto_sign_keypair(pk, sk);
}
