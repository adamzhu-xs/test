package com.example;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Main3 {
    public static void main(String argv[]) throws Exception {
        byte[] sharedSecret = "12345".getBytes();

        // Derive a key from the shared secret and both public keys
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);
        byte[] derivedKey = hash.digest();
        System.out.println(derivedKey[0]);

        String text = "123412341234";
        String iv = "1234567890123456";

        String enc = aesCbcEncryption(derivedKey, iv.getBytes(), text);
        System.out.println(enc);

        String dec = aesCbcDecrypt(derivedKey, iv.getBytes(), enc);
        System.out.println(dec);

        String encFromFe = "B15CGHzP8GADHaHoZbY2IQ==";
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
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(ivBytes));

        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String aesCbcDecrypt(byte[] key, byte[] ivBytes, String data)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(ivBytes));

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypted);
    }

}
