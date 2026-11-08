import java.security.KeyPairGenerator;
import javax.crypto.KEM;

class Main {
    void run() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM-768");
        KEM kem = KEM.getInstance("ML-KEM");
    }
}
