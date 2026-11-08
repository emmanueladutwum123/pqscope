import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

class Main {
    void make() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA");
        g.initialize(NamedParameterSpec.ML_DSA_87);
    }
}
