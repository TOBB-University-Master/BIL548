import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client {
    private static String response;
    private static Socket socket;
    private static BufferedReader userInput;
    private static PrintWriter out;
    private static BufferedReader in;
    public static void main(String[] args){
        String serverAddress = "127.0.0.1";
        int serverPort = 12345;
        userInput = new BufferedReader(new InputStreamReader(System.in));

        try {
            // Connecting to server ...
            connectToServer(serverAddress, serverPort);
            System.out.println("Sunucuya bağlanıldı: " + serverAddress + ":" + serverPort);

            // SSL/TLS handshake
            sendMessage("hello::new");

            while (true) {
                System.out.print("Komut girin (login, exit): ");
                String command = userInput.readLine();

                if (command.equals("login")) {
                    String encMessage = EncryptionHandler.encryptAES("login::kemal:12345");
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
     * Sunucuya bağlanmayı sağlar
     *
     * @throws IOException
     */
    private static void connectToServer(String serverAddress, int serverPort) throws IOException {
        if (socket!=null && socket.isConnected()) {
            System.out.println("Zaten sunucuya bağlısınız.");
            return;
        }
        socket = new Socket(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
    }


    /**
     * Sunucuya mesaj göndermek için kullanılır ve gelen mesajlarla ilgilenir
     *
     * @param message
     * @throws IOException
     */
    private static void sendMessage(String message) throws IOException {
        if (!socket.isConnected()) {
            System.out.println("Önce sunucuya bağlanmalısınız.");
            return;
        }

        if(message==null || message.length()==0){
            System.out.print("Göndermek istediğiniz mesajı girin: ");
            message = userInput.readLine();
        }

        System.out.println("\n********** TO SERVER **********");
        System.out.println(message);
        out.println(message);

        response = in.readLine();
        System.out.println("\n********** FROM SERVER **********");
        System.out.println(response);

        // sadece PK: varsa çalışır
        createSessionKey(response);
    }

    /**
     * Sunucudan gelen mesaj PK::MFkwEwY... formatında ise session key olarak AES anahtar oluştur
     *
     * @param serverMsg
     */
    private static void createSessionKey(String serverMsg){
        System.out.println("\n********** CLIENT INTERNAL OPS **********");
        if(serverMsg.contains("::") && serverMsg.split("::").length==2){
            String serverRequestCommand = serverMsg.split("::")[0];
            String serverRequestData = serverMsg.split("::")[1];
           if(serverRequestCommand.trim().equalsIgnoreCase("PK")){
               System.out.println("Generating session key AES... ");
               try{
                   EncryptionHandler.generateAESKey(128);
                   String AESSessionKeyBase64 = Base64.getEncoder().encodeToString(EncryptionHandler.sessionKey.getEncoded());
                   System.out.println("SessionKey::" + AESSessionKeyBase64);
                   String encryptedSessionKey = EncryptionHandler.encryptECDH(serverRequestData , AESSessionKeyBase64);
                   sendMessage("session::"+encryptedSessionKey);
               }catch (Exception e){
                    e.printStackTrace();
               }

           }
        }
    }

}
