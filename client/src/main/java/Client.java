import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.MarkerManager;
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
    private static final Logger logger = LogManager.getLogger(Client.class);

    public static HashMap<String, String> userPrivateKeyList;

    public static void main(String[] args){

        userPrivateKeyList = new HashMap<>();
        userPrivateKeyList.put("alice" , "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBhdKqaVFmgHvyPcX9L+tM5clYmppFvK8MEDWS0R7agqQ==");
        userPrivateKeyList.put("bob" , "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBRU3maSi+OhGkgLwNnbecco/O0LLwLV+D1C+2h12NnAA==");

        userInput = new BufferedReader(new InputStreamReader(System.in));
        clientConnectionState = ClientConnectionState.UNSECURE;

        // Long-term DH-EC anahtar ikilisi olusturulur
        keyPair = EncryptionHandler.generateECDHKeyPair();
        logger.info(MarkerManager.getMarker("GENERATE ECDH KEYPAIR"), "Sunucu sertifikası oluşturuldu");

        publicKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        logger.info(MarkerManager.getMarker("GENERATE ECDH PUBLIC"), "Public key[encoded] :: " + publicKeyEncoded);

        privateKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        logger.info(MarkerManager.getMarker("GENERATE ECDH PRIVATE"), "Private key[encoded] :: " + privateKeyEncoded);

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
            logger.warn(MarkerManager.getMarker("CONNECTION"), "Zaten sunucuya bağlısınız");
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
            logger.error(MarkerManager.getMarker("CONNECTION ERROR"), "NOT_CONNECTED");
            return;
        }

        out.println(message);
    }


}
