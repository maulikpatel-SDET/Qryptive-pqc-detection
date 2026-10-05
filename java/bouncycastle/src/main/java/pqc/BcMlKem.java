// TC-18  BouncyCastle (Java)  ML-KEM-768 key encapsulation.
package pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BcMlKem {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        KeyGenerator sender = KeyGenerator.getInstance("ML-KEM", "BC");
        sender.init(new KEMGenerateSpec(keyPair.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation senderKey = (SecretKeyWithEncapsulation) sender.generateKey();

        KeyGenerator receiver = KeyGenerator.getInstance("ML-KEM", "BC");
        receiver.init(new KEMExtractSpec(keyPair.getPrivate(), senderKey.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation receiverKey = (SecretKeyWithEncapsulation) receiver.generateKey();

        System.out.println("ML-KEM-768 keys match: "
                + Arrays.equals(senderKey.getEncoded(), receiverKey.getEncoded()));
    }
}
