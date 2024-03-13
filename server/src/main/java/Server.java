
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class Server {

    public static KeyPair keyPair;
    public static String publicKeyEncoded;
    public static String privateKeyEncoded;

    public static void main(String[] args){
        int port = 12345;
        try {
            Security.addProvider(new BouncyCastleProvider());
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Sunucu başlatıldı :: port " + port + " dinleniyor...");

            // Long-term DH-EC anahtar ikilisi olusturulur
            keyPair = createKeyPair();
            System.out.println("Sunucu sertifikası oluşturuldu :: ");

            publicKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            System.out.println("Public key[encoded] :: " + publicKeyEncoded);

            privateKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            System.out.println("Private key[encoded] :: " + privateKeyEncoded);

            // Server manage connections
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Yeni bir client bağlantısı alındı: " + clientSocket);

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static KeyPair createKeyPair() {
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

    public static String decryptMessage(String encryptedMessageBase64) throws Exception {
        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

}
