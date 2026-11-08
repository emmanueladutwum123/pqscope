import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;

class Main {
    void run() throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        Mac m = Mac.getInstance("HmacSHA256");
    }
}
