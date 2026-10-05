// TC-20  BouncyCastle (Java)  Falcon-512 signature.
package pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public class BcFalcon {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BCPQC");
        kpg.initialize(FalconParameterSpec.falcon_512, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] message = "qryptive pqc detection test".getBytes();

        Signature signer = Signature.getInstance("Falcon", "BCPQC");
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("Falcon", "BCPQC");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        System.out.println("Falcon-512 signature valid: " + verifier.verify(sig));
    }
}
