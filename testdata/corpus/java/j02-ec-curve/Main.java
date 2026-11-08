import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

class Main {
    void make() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        g.generateKeyPair();
    }
}
