import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;
import javax.crypto.KeyAgreement;

class Main {
    void run() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");
        g.initialize(NamedParameterSpec.X25519);
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
    }
}
