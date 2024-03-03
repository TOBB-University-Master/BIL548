import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    public static void main(String[] args){
        int port = 12345;
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Sunucu başlatıldı, port " + port + " dinleniyor...");

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

}
