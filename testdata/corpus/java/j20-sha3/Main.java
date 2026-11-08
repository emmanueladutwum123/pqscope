import java.security.MessageDigest;

class Main {
    byte[] h(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA3-256").digest(in);
    }
}
