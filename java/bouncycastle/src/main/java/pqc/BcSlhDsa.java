// TC-21  BouncyCastle (Java)  SLH-DSA (SPHINCS+) SHA2-128f signature.
package pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BcSlhDsa {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] message = "qryptive pqc detection test".getBytes();

        Signature signer = Signature.getInstance("SLH-DSA", "BC");
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SLH-DSA", "BC");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        System.out.println("SLH-DSA (SPHINCS+) SHA2-128f signature valid: " + verifier.verify(sig));
    }
}
