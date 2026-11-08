#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/dh.h>

int agree(void *out, const EC_POINT *pub, EC_KEY *key, DH *dh) {
    ECDH_compute_key(out, 32, pub, key, NULL);
    return DH_generate_key(dh);
}
