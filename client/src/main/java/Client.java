import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client {

    private static String response;
    private static Socket socket;
    private static BufferedReader userInput;
    private static PrintWriter out;
    private static BufferedReader in;
    public static void main(String[] args){
        String serverAddress = "localhost";
        int serverPort = 12345;

        try {
            socket = new Socket(serverAddress, serverPort);
            Security.addProvider(new BouncyCastleProvider());

            System.out.println("Sunucuya bağlanıldı: " + serverAddress + ":" + serverPort);

            userInput = new BufferedReader(new InputStreamReader(System.in));
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            while (true) {
                System.out.print("Komut girin (connect, send, exit): ");
                String command = userInput.readLine();

                if (command.equals("connect")) {
                    connectToServer();
                } else if (command.equals("send")) {
                    sendMessage(null);
                } else if (command.equals("login")) {
                    String encMessage = encryptMessageStr(response,"kemal");
                    sendMessage(encMessage);
                } else if (command.equals("exit")) {
                    System.out.println("Programdan çıkılıyor...");
                    break;
                } else {
                    System.out.println("Geçersiz komut!");
                }
            }

            userInput.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Sunucu tarafından gelen public key ile String message Encrypt edilir
     */
    private static String encryptMessageStr(String serverPublicKeyEncoded , String message) throws Exception{
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeyEncoded);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);

        // Mesajı şifrele
        byte[] encryptedMessage = encryptMessage(message, serverPublicKey);

        // Şifreli mesajı Base64 formatına dönüştürerek göster
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);
        return encryptedMessageBase64;
    }

    private static byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }


    /**
     *
     * @throws IOException
     */
    private static void connectToServer() throws IOException {
        if (socket.isConnected()) {
            System.out.println("Zaten sunucuya bağlısınız.");
            return;
        }

        System.out.print("Sunucuya bağlanmak için IP adresi/alan adı girin: ");
        String serverAddress = userInput.readLine();
        System.out.print("Sunucu port numarası girin: ");
        int serverPort = Integer.parseInt(userInput.readLine());

        socket = new Socket(serverAddress, serverPort);
        System.out.println("Sunucuya bağlanıldı: " + serverAddress + ":" + serverPort);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
    }

    private static void sendMessage(String message) throws IOException {
        if (!socket.isConnected()) {
            System.out.println("Önce sunucuya bağlanmalısınız.");
            return;
        }

        System.out.print("Göndermek istediğiniz mesajı girin: ");
        message = message==null || message.length()==0 ? userInput.readLine():message;
        out.println(message);

        response = in.readLine();
        response = response.contains(":") ? response.split(":")[1].trim() : response;
        System.out.println("Sunucudan gelen cevap: " + response);
    }

}
