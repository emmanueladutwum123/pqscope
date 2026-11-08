import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;

class Main {
    void make() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(new RSAKeyGenParameterSpec(3072, BigInteger.valueOf(65537)));
    }
}
