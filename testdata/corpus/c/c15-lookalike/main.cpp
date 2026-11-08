namespace mylib {
int MD5(const char *s);
}

struct Keys { int (*RSA_new)(void); };

int run(Keys *k) {
    k->RSA_new();
    return mylib::MD5("x");
}
