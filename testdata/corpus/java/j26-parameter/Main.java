import java.security.MessageDigest;

class Main {
    byte[] digest(String alg, byte[] in) throws Exception {
        return MessageDigest.getInstance(alg).digest(in);
    }
    byte[] sha1(byte[] in) throws Exception {
        return digest("SHA-1", in);
    }
}
