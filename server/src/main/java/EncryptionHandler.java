import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptionHandler {

    public SecretKey sessionKey;

    public static KeyPair keyPair;
    public static String publicKeyEncoded;
    public static String privateKeyEncoded;

    /**
     *  Generate AES key for session
     */
    public void generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        sessionKey = keyGen.generateKey();
    }

    public void setAESKey(String secretKeyString){
        byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
        sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }


    /**
     *  Metin dizesini AES kullanarak şifrele
     */
    public String encryptAES(String strToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }


    /**
     *  Şifrelenmiş metni AES kullanarak çöz
     */
    public String decryptAES(String strToDecrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(strToDecrypt));
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

    public static String decryptECDH(String encryptedMessageBase64) throws Exception {
        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }


    /**
     * Sunucu tarafından gelen public key ile String message Encrypt edilir
     */
    public static String encryptECDH(String publicKeyEncoded , String message) throws Exception{
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

}
