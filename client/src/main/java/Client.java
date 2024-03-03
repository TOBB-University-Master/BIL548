import java.io.*;
import java.net.Socket;

public class Client {

    private static Socket socket;
    private static BufferedReader userInput;
    private static PrintWriter out;
    private static BufferedReader in;
    public static void main(String[] args){
        String serverAddress = "localhost";
        int serverPort = 12345;

        try {
            socket = new Socket(serverAddress, serverPort);
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
                    sendMessage();
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
        }
    }

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

    private static void sendMessage() throws IOException {
        if (!socket.isConnected()) {
            System.out.println("Önce sunucuya bağlanmalısınız.");
            return;
        }

        System.out.print("Göndermek istediğiniz mesajı girin: ");
        String message = userInput.readLine();
        out.println(message);

        String response = in.readLine();
        System.out.println("Sunucudan gelen cevap: " + response);
    }

}
