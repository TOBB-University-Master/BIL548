
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.util.*;

public class Server {

    public static HashMap<String, User> userDatabase = new HashMap<>();

    public static HashMap< String ,User> onlineUserList = new HashMap<>();
    public static KeyPair keyPair;
    public static String publicKeyEncoded;
    public static String privateKeyEncoded;
    public static List<ClientHandler> clientSocketList = new ArrayList<>();

    public static void main(String[] args){
        int port = 12345;

        User user1 = new User("1", "alice", "12345");    // password 12345
        User user2 = new User("2", "bob", "12345" );
        User user3 = new User("3", "karaca", "12345");

        userDatabase.put(user1.getUsername(), user1);
        userDatabase.put(user2.getUsername(), user2);
        userDatabase.put(user3.getUsername(), user3);

        try {
            Security.addProvider(new BouncyCastleProvider());
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Sunucu başlatıldı :: port " + port + " dinleniyor...");

            // Long-term DH-EC anahtar ikilisi olusturulur
            keyPair = EncryptionHandler.generateECDHKeyPair();
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
