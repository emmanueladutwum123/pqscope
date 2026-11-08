#include <openssl/md5.h>

void legacy(const unsigned char *in, size_t n, unsigned char *out) {
#if 0
    MD5(in, n, out);
#endif
    if (0) {
        SHA1(in, n, out);
    }
}
