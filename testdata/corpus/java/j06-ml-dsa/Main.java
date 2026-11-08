import java.security.KeyPairGenerator;
import java.security.Signature;

class Main {
    void run() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA-65");
        Signature s = Signature.getInstance("ML-DSA");
    }
}
