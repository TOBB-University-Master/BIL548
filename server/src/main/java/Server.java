
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.util.*;

public class Server {

    public static String SERVER_PRIVATE_KEY = "SERVER_PRIVATE_KEY";
    public static HashMap<String, User> userDatabase = new HashMap<>();
    public static HashMap< String ,User> onlineUserList = new HashMap<>();
    public static KeyPair keyPair;
    public static String publicKeyEncoded;
    public static String privateKeyEncoded;
    public static List<ClientHandler> clientSocketList = new ArrayList<>();
    private static final Logger logger = LogManager.getLogger(Server.class);
    private static final Marker NEW_CONNECTION = MarkerManager.getMarker("NEW CONNECTION");

    public static void main(String[] args){
        int port = 12345;

        User user1 = new User("1", "alice", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt1MLjZaxpFQ8kzdAw+hSpin+g1F5NULKvISuIYK2HOgxUFznrIppN6mbuaFwLvrGxN/x5J85oyIQJrQlI/DvaQ==");
        User user2 = new User("2", "bob", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXNRxrDdbVdc/bIXWwC9oGL5EKWEQxvOcPj+9MvOfOIw0V5yiXwFAnlCGi3uirAkJYh9TZwqQrUHStC4iLQZ6hA==" );
        User user3 = new User("3", "karaca", "12345");

        userDatabase.put(user1.getUsername(), user1);
        userDatabase.put(user2.getUsername(), user2);
        userDatabase.put(user3.getUsername(), user3);

        try {
            Security.addProvider(new BouncyCastleProvider());
            ServerSocket serverSocket = new ServerSocket(port);
            logger.info("Sunucu başlatıldı :: port " + port + " dinleniyor...");

            // Long-term DH-EC anahtar ikilisi olusturulur
            keyPair = EncryptionHandler.generateECDHKeyPair();
            logger.info("Sunucu sertifikası oluşturuldu");

            publicKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            logger.info("Public key[encoded] :: " + publicKeyEncoded);

            privateKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            logger.info("Private key[encoded] :: " + privateKeyEncoded);

            // Server manage connections
            while (true) {
                Socket clientSocket = serverSocket.accept();
                logger.info(NEW_CONNECTION , "Yeni bir client bağlantısı alındı: " + clientSocket);

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread thread = new Thread(clientHandler);
                clientSocketList.add(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void broadcast(String message) {
        for (ClientHandler client : clientSocketList) {
            client.sendMessage(message);
        }
    }

    public static void broadcastEnc(String message) throws Exception{
        for (ClientHandler client : clientSocketList) {
            client.sendMessage(EncryptionHandler.encryptAES(client.user.getSessionKey() ,message));
        }
    }

    public static void broadcastTo(String username,String message){
        for (ClientHandler client : clientSocketList) {
            if(client.user.getUsername().equalsIgnoreCase(username)){
                client.sendMessage(message);
            }
        }
    }

    public static void broadcastToEnc(String username,String message) throws Exception{
        for (ClientHandler client : clientSocketList) {
            if(client.user.getUsername().equalsIgnoreCase(username)){
                client.sendMessage(EncryptionHandler.encryptAES(client.user.getSessionKey() ,message));
            }
        }
    }

}
