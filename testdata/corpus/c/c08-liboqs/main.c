#include <oqs/oqs.h>

void pqc(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
}
