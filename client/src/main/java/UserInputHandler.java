import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;

public class UserInputHandler implements Runnable {
    private BufferedReader userInput;
    private PrintWriter out;

    public UserInputHandler(BufferedReader userInput, PrintWriter out) {
        this.userInput = userInput;
        this.out = out;
    }

    @Override
    public void run() {
        try {
            while (true) {
                System.out.print("Komut girin (user_list , chat): ");
                String command = userInput.readLine();

                if (command.equals("login")) {
                    /**
                     * Simetrik anahtar ile kullanıcı login olur
                     */
                    String encMessage = EncryptionHandler.encryptAES("login::kemal:12345");
                    Client.sendMessageToServer(encMessage);

                    // Bu servis ile kullanıcı listesi alınıyor
                } else if (command.equals("user_list")) {
                    String encMessage = EncryptionHandler.encryptAES("user_list::new");
                    Client.sendMessageToServer(encMessage);

                    // Bu servis ile kullanıcı listesi alınıyor
                } else if (command.equals("chat")) {
                    System.out.print("Kullanıcı id girin :");
                    String user = userInput.readLine();
                    String encMessage = EncryptionHandler.encryptAES("chat::new::" + Client.publicKeyEncoded + "::" + user);
                    // Client.sendMessage(encMessage);
                    sendMessage(encMessage);

                } else if (command.equals("exit")) {
                    System.out.println("Programdan çıkılıyor...");
                    break;
                } else {
                    System.out.println("Geçersiz komut!");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Sunucuya mesaj göndermek için kullanılır ve gelen mesajlarla ilgilenir
     *
     * @param message
     * @throws IOException
     */
    public void sendMessage(String message) throws IOException,Exception {

        if(message==null || message.length()==0){
            System.out.print("Göndermek istediğiniz mesajı girin: ");
            message = userInput.readLine();
        }

        System.out.println("\n********** TO SERVER **********");
        System.out.println(message);
        out.println(message);
    }
}