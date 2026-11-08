import javax.crypto.Cipher;

class Main {
    void run() throws Exception {
        String t = "AES_128/GCM/NoPadding";
        Cipher c = Cipher.getInstance(t);
    }
}
