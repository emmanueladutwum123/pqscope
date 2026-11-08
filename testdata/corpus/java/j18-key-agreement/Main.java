import javax.crypto.KeyAgreement;

class Main {
    void run() throws Exception {
        KeyAgreement e = KeyAgreement.getInstance("ECDH");
        KeyAgreement d = KeyAgreement.getInstance("DiffieHellman");
    }
}
