import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ClientHandler implements Runnable {

    private static KeyPair keyPair;
    private Socket clientSocket;

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("Client'dan gelen mesaj: " + line);

                String response = "";
                if (line.equals("create-key")) {
                    KeyPair keyPair = createKeyPair();
                    // Sunucu genel anahtarını istemciye gönder
                    String publicKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
                    response = publicKeyEncoded;

                    String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
                    System.out.println("PRIVATE KEY: " + privateKey);
                    out.println("RESPONSE: " + response);

                } else {
                    String decMessage = decryptMessage(line);
                    System.out.println("Decrypted message : " + decMessage);
                    System.out.println("Client request error...");
                    out.println("RESPONSE: REQUEST NOT FOUND ERROR");
                }

            }

            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e){
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

    private static String decryptMessage(String encryptedMessageBase64) throws Exception {
        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

}
