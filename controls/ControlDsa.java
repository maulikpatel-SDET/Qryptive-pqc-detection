// TC-28  CONTROL - classical DSA-2048. Qryptive SHOULD flag this as quantum-vulnerable.
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class ControlDsa {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Signature s = Signature.getInstance("SHA256withDSA");
        s.initSign(kp.getPrivate());
        s.update("control".getBytes());
        System.out.println("DSA signature length: " + s.sign().length);
    }
}
