#include <openssl/evp.h>

void run() {
    auto cipher = EVP_aes_128_gcm();
    auto md = EVP_sha384();
    auto ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
}
