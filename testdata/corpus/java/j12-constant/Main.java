import java.security.KeyPairGenerator;

class Main {
    static final String ALG = "RSA";

    void run() throws Exception {
        KeyPairGenerator.getInstance(ALG);
    }
}
