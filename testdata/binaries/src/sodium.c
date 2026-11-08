/* Imports libsodium functions so the binary lists them. Never run. */
#include <sodium.h>

int main(int argc, char **argv) {
	unsigned char pk[32], sk[64], m[1], c[64];
	unsigned long long clen;
	(void)argv;
	if (argc > 99) {
		crypto_box_keypair(pk, sk);
		crypto_sign_detached(c, NULL, m, 1, sk);
		crypto_aead_chacha20poly1305_ietf_encrypt(c, &clen, m, 1, NULL, 0, NULL, pk, sk);
	}
	return 0;
}
