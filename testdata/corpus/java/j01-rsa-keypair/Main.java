import java.security.KeyPair;
import java.security.KeyPairGenerator;

class Main {
    KeyPair make() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }
}
