import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
public class EncryptionHandler {

    public static SecretKey sessionKey;


    /**
     *  Generate AES key for session
     */
    public static void generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        sessionKey = keyGen.generateKey();
    }


    /**
     *  Metin dizesini AES kullanarak şifrele
     */
    public static String encryptAES(String strToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }


    /**
     *  Şifrelenmiş metni AES kullanarak çöz
     */
    public static String decryptAES(String strToDecrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(strToDecrypt));
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
