import java.security.KeyPairGenerator;
import java.security.Signature;

class Main {
    void run() throws Exception {
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Signature.getInstance("Ed25519");
    }
}
