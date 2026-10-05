// TC-19  BouncyCastle (Java)  ML-DSA-65 signature.
package pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BcMlDsa {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] message = "qryptive pqc detection test".getBytes();

        Signature signer = Signature.getInstance("ML-DSA", "BC");
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ML-DSA", "BC");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        System.out.println("ML-DSA-65 signature valid: " + verifier.verify(sig));
    }
}
