import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

class Main {
    void run() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA512");
        Mac m = Mac.getInstance("HmacSHA512");
    }
}
