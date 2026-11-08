#include <openssl/evp.h>
#include <openssl/ec.h>

void make(void) {
    EVP_PKEY *k = EVP_EC_gen("P-384");
    EC_KEY *old = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}
