import javax.crypto.Cipher;

class Main {
    void run() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        Cipher r = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
}
