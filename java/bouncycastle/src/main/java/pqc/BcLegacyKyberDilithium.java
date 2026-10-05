// TC-22  BouncyCastle (Java)  OLD names: Kyber768 + Dilithium3 via BCPQC provider.
// Purpose: pre-standard names must also be recognised as PQC.
package pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

public class BcLegacyKyberDilithium {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());

        KeyPairGenerator kyberKpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kyberKpg.initialize(KyberParameterSpec.kyber768, new SecureRandom());
        KeyPair kyberKeys = kyberKpg.generateKeyPair();
        System.out.println("Kyber768 key generated: " + kyberKeys.getPublic().getAlgorithm());

        KeyPairGenerator dilKpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        dilKpg.initialize(DilithiumParameterSpec.dilithium3, new SecureRandom());
        KeyPair dilKeys = dilKpg.generateKeyPair();

        Signature s = Signature.getInstance("Dilithium", "BCPQC");
        s.initSign(dilKeys.getPrivate());
        s.update("legacy names".getBytes());
        byte[] sig = s.sign();
        s.initVerify(dilKeys.getPublic());
        s.update("legacy names".getBytes());
        System.out.println("Dilithium3 signature valid: " + s.verify(sig));
    }
}
