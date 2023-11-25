package com.example;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Main2 {
    public static void main2(String argv[]) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec secp521r1 = new ECGenParameterSpec("secp521r1");
        kpg.initialize(secp521r1);

        KeyPair kp = kpg.generateKeyPair();
        String x509DerFromJava = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        String pkcs8DerFromJava = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        System.out.println(x509DerFromJava);
        System.out.println(pkcs8DerFromJava);
    }

    public static void main(String argv[]) throws Exception {

        String pubkey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAr8gxZn13MCIx5TBoCIrp7noLxmryWGOjv62byFJl2+muPTo6GzJPE2uVW9Pay8zifAVEW9zNB7muqZ9r94Vw2T0AW7KeE+B578ieHRDHKqTPfEuNPW658XOApy/j3ghkfWsrJqYmPkmde0lPs+x1F1YgRd7MI5LCU+Cko3tY87ZwOY8=";
        String prikey = "MGACAQAwEAYHKoZIzj0CAQYFK4EEACMESTBHAgEBBEIAYjVtdZeGMtJddegoMtvrfJkK5HGLC+pyyQnpL8wWbfBwEpmwBkkogXwOU+JeviH7kD52rDJYMLcvX6/A86E8X3Y=";

        String x509PemFromDart = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAjv5LOt9mYjvlpWWIxdahNHU6b3ENSM57WsLILZaq+0GRPBrvpEC50RQ6wJYqHizd0vTATOJ6JorqFldXTCTAAy0BGzcLImdSMrMwCZf8M0JAmRSo3T2qyF4NBxquLBMaI3a77Mo5939Mjmcjy8ke3cRNnnUdgL0Y6lJuiSyOUXo9yis=";
        byte[] x509DerFromDart = Base64.getDecoder().decode(x509PemFromDart);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey x509FromDart = kf.generatePublic(new X509EncodedKeySpec(x509DerFromDart));
        byte[] pkcs8DerFromJava = Base64.getDecoder()
                .decode(prikey);
        PrivateKey pkcs8FromJava = kf
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8DerFromJava));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(pkcs8FromJava);
        keyAgreement.doPhase(x509FromDart, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        BigInteger bi = new BigInteger(sharedSecret);
        System.out.println(bi.toString(16));

        // Derive a key from the shared secret and both public keys
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(bi.toString(16).getBytes());
        byte[] derivedKey = hash.digest();
        System.out.println(derivedKey[0]);

        // System.out.println(toHexString(sharedSecret));
        // 000D435420EE5DCF640C9867CCFD4EAC88571EAFF95F64A1F697B0E78082898061FB5E1A8734317632E673A15DC104119F97912C3DCA5C199162EDB73A01E7AE75CA
        // d435420ee5dcf640c9867ccfd4eac88571eaff95f64a1f697b0e78082898061fb5e1a8734317632e673a15dc104119f97912c3dca5c199162edb73a01e7ae75ca

        String text = "123412341234";
        String iv = "1234567890123456";

        String enc = aesCbcEncryption(derivedKey, iv.getBytes(), text);
        System.out.println(enc);

        String dec = aesCbcDecrypt(derivedKey, iv.getBytes(), enc);
        System.out.println(dec);

        String encFromFe = "ghPfffLVA+sJNHuzxJYEaw==";
        System.out.println(Base64.getDecoder().decode(encFromFe)[0]);
        String dec1 = aesCbcDecrypt(derivedKey, iv.getBytes(), encFromFe);
        System.out.println(dec1);
    }

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static String aesCbcEncryption(byte[] key, byte[] ivBytes, String data)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String aesCbcDecrypt(byte[] key, byte[] ivBytes, String data)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypted);
    }

}
