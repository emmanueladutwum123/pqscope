import java.security.MessageDigest;

class Main {
    byte[] legacy(byte[] in) throws Exception {
        MessageDigest.getInstance("MD5").digest(in);
        return MessageDigest.getInstance("SHA-1").digest(in);
    }
}
