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
    public static String aliceBobCR = null;
    public static SecretKey chatSecretKey = null;
    public static String chatState = null;
    public static String username = null;
    public static String TGT = null;
    public static SecretKey longTermSecretKey = null;
    public static String nonce = null;
    public static String session = null;
    public static String sessionTimestamp = null;
    public static SecretKey sessionKey=null;
    public static KeyPair keyPair;
    public static String publicKeyEncoded;
    public static String privateKeyEncoded;
    private static Socket socket;
    public static BufferedReader userInput;
    private static PrintWriter out;
    private static BufferedReader in;
    public static ClientConnectionState clientConnectionState;
    public static MessageReceiver messageReceiver;
    public static UserInputHandler userInputHandler;

    public static String chatSessionKey;
    public static String chatUserName;

    public static void main(String[] args){
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
            // Connecting to server ...
            connectToServer(serverName, serverPort);

            // Sunucudan gelen mesajları işleyen thread
            messageReceiver = new MessageReceiver(in);
            Thread messageThread = new Thread(messageReceiver);
            messageThread.start();

            // Kullanıcı girdisini işleyen thread
            userInputHandler = new UserInputHandler(userInput, out);
            Thread userInputThread = new Thread(userInputHandler);
            userInputThread.start();

            messageThread.join();
            userInputThread.join();

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
        if (socket!=null && socket.isConnected() && !socket.isClosed()) {
            System.out.println("Zaten sunucuya bağlısınız.");
            return;
        }
        socket = new Socket(serverAddress, serverPort);
        Security.addProvider(new BouncyCastleProvider());
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
    }

    /**
     * Sunucu bağlantı kapatma fonksiyonudur
     */
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

        // System.out.println("\n********** TO SERVER **********");
        // System.out.println(message);
        out.println(message);
    }


}
