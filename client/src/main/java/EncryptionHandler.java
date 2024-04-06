import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
public class EncryptionHandler {

    public static String serverEncodedPublicKey;
    public static KeyPair keyPair;

    /**
     *  Generate AES key for session
     */
    public static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

/*
    public static SecretKey getAESKey(String secretKeyString){
        byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
        SecretKey sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return sessionKey;
    }
     */

    /**
     *  Metin dizesini AES kullanarak şifrele
     */
    public static String getTextMAC(SecretKey secretKey, String text) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] macBytes = mac.doFinal(text.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : macBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static SecretKey getAESKey(String secretKeyString){
        try{
            // secretKeyString to byte
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] salt = new byte[16];
            // Optional
            PBEKeySpec spec = new PBEKeySpec(secretKeyString.toCharArray(), salt, 10000, 128);
            SecretKey secretKey = factory.generateSecret(spec);

            byte[] encodedKey = secretKey.getEncoded();
            return new SecretKeySpec(encodedKey, "AES");

            // byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
            // SecretKey sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            // return sessionKey;
        } catch (Exception e){
            return null;
        }
    }


    /**
     *  Metin dizesini AES kullanarak şifrele
     */
    public static String encryptAES(SecretKey sessionKey, String strToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }


    /**
     *  Şifrelenmiş metni AES kullanarak çöz
     */
    public static String decryptAES(SecretKey sessionKey, String strToDecrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(strToDecrypt));
        return new String(decryptedBytes);
    }


    /**
     * Sunucu tarafından gelen public key ile String message Encrypt edilir
     */
    public static String encryptECDH(String publicKeyEncoded , String message) throws Exception{
        Security.addProvider(new BouncyCastleProvider());

        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(publicKeyEncoded);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);

        // Mesajı şifrele
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        // Encode to base64
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);
        return encryptedMessageBase64;
    }

    public static String decryptECDH(String privateKeyEncoded , String encryptedMessageBase64) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyEncoded);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey clientPrivateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        //byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(privateKeyEncoded);
        //X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPrivateKeyBytes);
        //KeyFactory keyFactory = KeyFactory.getInstance("EC");
        //PrivateKey clientPrivateKey = keyFactory.generatePrivate(x509KeySpec);

        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    public static KeyPair generateECDHKeyPair() {
        try{
            // Generate EC key
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec parameterSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(parameterSpec);
            keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;
        }catch (Exception e){
            return null;
        }
    }

}
