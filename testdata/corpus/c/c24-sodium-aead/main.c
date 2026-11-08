#include <sodium.h>

void run(unsigned char *c, unsigned long long *clen, const unsigned char *m, const unsigned char *n, const unsigned char *k, unsigned char *pk, unsigned char *sk) {
    crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, 1, NULL, 0, NULL, n, k);
    crypto_aead_aes256gcm_encrypt(c, clen, m, 1, NULL, 0, NULL, n, k);
    crypto_kx_keypair(pk, sk);
}
