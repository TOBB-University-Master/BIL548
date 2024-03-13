import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientHandler implements Runnable {

    private Socket clientSocket;

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    /**
     *
     * client gelen veri aşağıdaki formatta olmalıdır
     *
     * command::data
     */
    @Override
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            String line;
            String decMessage;
            while ((line = in.readLine()) != null) {
                System.out.println("Client'dan gelen mesaj: " + line);
                String[] request = line.split("::");
                decMessage=null;
                if(request.length==2){
                    String command = request[0];
                    String data = request[1];

                    switch (command){
                        case "hello":
                            out.println("PK::" + Server.publicKeyEncoded);
                            break;

                        case "session":
                            decMessage = Server.decryptMessage(data);
                            System.out.println("Session Key : " + decMessage);
                            out.println("RESPONSE: hello done...");
                            break;

                        case "login":
                            // TODO: Burada AES decryption yapılacak...
                            out.println("Burada AES decryption yapılacak...");
                            break;

                        default:
                            out.println("RESPONSE: REQUEST NOT FOUND ERROR");
                            break;
                    }

                } else {
                    out.println("RESPONSE:REQUEST FORMAT MUST {command::data}");
                }

            }

            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
    }


}
