import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

public class Client {

    private static String serverName="127.0.0.1";;
    private static int serverPort=12345;
    private static String userId = null;
    public static KeyPair keyPair;
    public static String publicKeyEncoded;
    public static String privateKeyEncoded;
    private static String response;
    private static Socket socket;
    private static BufferedReader userInput;
    private static PrintWriter out;
    private static BufferedReader in;
    public static ClientConnectionState clientConnectionState;
    public static void main(String[] args){
        Client client = new Client();
        userInput = new BufferedReader(new InputStreamReader(System.in));
        clientConnectionState = ClientConnectionState.UNSECURE;

        // Long-term DH-EC anahtar ikilisi olusturulur
        keyPair = EncryptionHandler.generateECDHKeyPair();
        System.out.println("Sunucu sertifikası oluşturuldu :: ");

        publicKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        System.out.println("Public key[encoded] :: " + publicKeyEncoded);

        privateKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        System.out.println("Private key[encoded] :: " + privateKeyEncoded);

        try {
            // Connection Protocol
            connectionProtocol();

/*
            // Sunucudan gelen mesajları işleyen thread
            MessageReceiver messageReceiver = new MessageReceiver(in);
            Thread messageThread = new Thread(messageReceiver);
            messageThread.start();

            // Kullanıcı girdisini işleyen thread
            UserInputHandler userInputHandler = new UserInputHandler(userInput, out);
            Thread userInputThread = new Thread(userInputHandler);
            userInputThread.start();

            messageThread.join();
            userInputThread.join();
 */

            while (true) {
                System.out.print("Komut girin (login , user_list): ");
                String command = userInput.readLine();

                if (command.equals("login")) {
                    loginProtocol();

                // Bu servis ile kullanıcı listesi alınıyor
                } else if (command.equals("user_list")) {
                    String encMessage = EncryptionHandler.encryptAES("user_list::new");
                    sendMessageToServer(encMessage);

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
     * Bu protokol ile Client-Server güvenli bağlantı için anahtar değişimi sağlanır
     */
    private static void connectionProtocol() throws Exception{
        // Connecting to server ...
        connectToServer(serverName, serverPort);
        System.out.println("\n********** CONNECTION PROCOTOL STARTED **********");
        System.out.println("Sunucuya bağlanıldı: " + serverName + ":" + serverPort);

        // SSL/TLS handshake start
        sendMessageToServer("hello::new");

        // SSL/TLS handshake session key selection
        if(clientConnectionState==ClientConnectionState.SSL_HANDSHAKE){
            System.out.println("Generating session key AES... ");
            EncryptionHandler.generateAESKey(128);
            String AESSessionKeyBase64 = Base64.getEncoder().encodeToString(EncryptionHandler.sessionKey.getEncoded());
            System.out.println("SessionKey::" + AESSessionKeyBase64);
            String encryptedSessionKey = EncryptionHandler.encryptECDH(EncryptionHandler.serverEncodedPublicKey , AESSessionKeyBase64);
            sendMessageToServer(encryptedSessionKey);
        } else {
            throw new Exception("SSL_HANDSHAKE_ERROR!!!");
        }

        // Close connection after session key
        closeConnection();
        System.out.println("\n********** CONNECTION PROCOTOL FINISHED **********");
    }


    /**
     * Bu protokol ile Client-Server güvenli bağlantı için anahtar değişimi sağlanır
     */
    private static void loginProtocol() throws Exception{
        connectToServer(serverName, serverPort);
        System.out.println("\n********** LOGIN PROCOTOL STARTED **********");

        /**
         * Simetrik anahtar ile kullanıcı login olur
         */
        JSONObject encJsonData = new JSONObject();
        encJsonData.put("username", "kemal");
        encJsonData.put("password", "12345");
        encJsonData.put("command", "login");

        String encMessage = EncryptionHandler.encryptAES(encJsonData.toString());
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("from", userId);
        jsonObject.put("data", encMessage);
        sendMessageToServer(jsonObject.toString());

        // Close connection after login
        closeConnection();
        System.out.println("\n********** LOGIN PROCOTOL FINISHED **********");
    }


    /**
     * Sunucuya bağlanmayı sağlar
     *
     * @throws IOException
     */
    private static void connectToServer(String serverAddress, int serverPort) throws IOException {
        if (socket!=null && socket.isConnected() && !socket.isClosed()) {
            System.out.println("Zaten sunucuya bağlısınız.");
            return;
        }
        socket = new Socket(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
    }

    private static void closeConnection() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * Sunucuya mesaj göndermek için kullanılır ve gelen mesajlarla ilgilenir
     *
     * @param message
     * @throws IOException
     */
    public static void sendMessageToServer(String message) throws Exception {
        if (!socket.isConnected()) {
            System.out.println("ERROR:NOT_CONNECTED");
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

        // handle messages from server
        handleMessage(response);
    }

    /**
     * Gelen mesajları yöneten fonksiyon
     *
     * @param message
     * @return
     */
    public static void handleMessage(String message) throws Exception{
        String command = null;
        String[] response;
        switch (clientConnectionState) {

            // sadece PK: varsa çalışır
            case UNSECURE:
                // createSessionKey(message);
                System.out.println("\n********** CLIENT INTERNAL OPS **********");
                if(message.contains("::") && message.split("::").length==2){
                    String serverRequestCommand = message.split("::")[0];
                    if(serverRequestCommand.trim().equalsIgnoreCase("PK")){
                        EncryptionHandler.serverEncodedPublicKey = message.split("::")[1];
                        clientConnectionState = ClientConnectionState.SSL_HANDSHAKE;
                    }
                }
                break;

            case SSL_HANDSHAKE:
                response = message.split("::");
                if(response.length==3 && response[0].equalsIgnoreCase("hello") && response[1].equalsIgnoreCase("done")){
                    clientConnectionState = ClientConnectionState.SESSION_KEY;
                    userId = response[2];
                }
                break;

            case SESSION_KEY:
                String plainText = EncryptionHandler.decryptAES(message);
                System.out.println(plainText);
                break;
        }
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
                   clientConnectionState = ClientConnectionState.SSL_HANDSHAKE;
                   //sendMessageToServer(encryptedSessionKey);
               }catch (Exception e){
                    e.printStackTrace();
               }

           }
        }
    }

}
