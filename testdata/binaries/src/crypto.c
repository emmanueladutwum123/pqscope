/*
 * Imports OpenSSL functions so the linked binary lists them as dynamic
 * imports. It is never run; pqscope only parses it. Prototypes are declared
 * here rather than included, so the same file builds for ELF, PE and Mach-O.
 */
#include <stddef.h>

void *RSA_new(void);
int RSA_generate_key_ex(void *rsa, int bits, void *e, void *cb);
int ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, void *eckey);
const void *EVP_sha256(void);
const void *EVP_aes_256_gcm(void);
const void *EVP_md5(void);
int EVP_PKEY_encapsulate(void *ctx, unsigned char *wrapped, size_t *wlen, unsigned char *gen, size_t *glen);

int main(int argc, char **argv) {
	(void)argv;
	if (argc < 0) { /* never true: the calls exist only to be linked */
		RSA_generate_key_ex(RSA_new(), 2048, NULL, NULL);
		ECDSA_sign(0, NULL, 0, NULL, NULL, NULL);
		EVP_sha256();
		EVP_aes_256_gcm();
		EVP_md5();
		EVP_PKEY_encapsulate(NULL, NULL, NULL, NULL, NULL);
	}
	return 0;
}
