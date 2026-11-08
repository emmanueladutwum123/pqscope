import javax.crypto.Cipher;

class Main {
    void run() throws Exception {
        Cipher.getInstance("RC4");
        Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
