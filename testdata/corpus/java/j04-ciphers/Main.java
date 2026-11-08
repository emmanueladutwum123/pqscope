import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

class Main {
    void run() throws Exception {
        Cipher a = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher t = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        KeyGenerator k = KeyGenerator.getInstance("AES");
        k.init(256);
    }
}
