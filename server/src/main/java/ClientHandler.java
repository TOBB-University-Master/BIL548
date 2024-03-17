import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientHandler implements Runnable {

    public String username;
    public int id;
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private ClientConnectionState clientConnectionState;

    private EncryptionHandler encryptionHandler;

    public ClientHandler(Socket clientSocket) {
        this.id = (int)(Math.random() * (100000) + 1);
        this.username = "user_" + id ;
        this.clientSocket = clientSocket;
        // Initial state for Client
        this.clientConnectionState = ClientConnectionState.UNSECURE;
        this.encryptionHandler = new EncryptionHandler();
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
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            String line;
            while ((line = in.readLine()) != null) {
                handleMessage(line);
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

    public void sendMessage(String message) {
        out.println(message);
    }

    /**
     * Client tarafından gelen mesajları işleme alır
     *
     * Gelen istek command::param1::param2::param3:: şeklinde olmalıdır
     *
     * @param message
     */
    private void handleMessage(String message) throws Exception{
        System.out.println("\nCLIENT REQUEST MSG: " + message);

        String response = "RESPONSE:REQUEST FORMAT MUST {command::data}";
        String command = null;
        String[] request;

        switch (clientConnectionState) {

            // Public key send to client
            case UNSECURE:
                request = message.split("::");
                if(request!=null && request.length>0){
                    command = request[0];
                    if(command.equalsIgnoreCase("hello")){
                        response = "PK::" + Server.publicKeyEncoded;
                        clientConnectionState = ClientConnectionState.SSL_HANDSHAKE_START;
                    }
                }
                break;

            case SSL_HANDSHAKE_START:
                //String decMessage = Server.decryptMessage(message);
                String sessionKey = EncryptionHandler.decryptECDH(message);
                encryptionHandler.setAESKey(sessionKey);
                System.out.println("Session Key : " + sessionKey);
                clientConnectionState = ClientConnectionState.SESSION_KEY;
                response = "hello::done";
                break;

            // All messages will be encrypted
            case SESSION_KEY:
                String plainText = encryptionHandler.decryptAES(message);
                System.out.println("PLAIN TEXT : " + plainText);
                request = plainText.split("::");
                if(request!=null && request.length>0){
                    switch (request[0]){

                        case "login":
                            if(request.length==3){
                                String username = request[1];
                                String password = request[2];

                                User user = Server.userMap.get(username);
                                if(user==null){
                                    response = "RESPONSE::USER_NOT_FOUND";
                                } else if(user.getPassword()!=password){
                                    response = "RESPONSE::USER_PASSWORD_WRONG";
                                } else {
                                    // TODO: Burada kullanıcı için authentication sağlanacak
                                    // JWT gibi kullanıcı adı ve imzası imzalanacak
                                    System.out.println();
                                }
                            } else {
                                response = "RESPONSE::PARAMETER_ERROR";
                            }
                            break;

                        case "user_list":
                            response = getUserList();
                            System.out.println(response);
                            break;

                        default:
                            response = "RESPONSE: REQUEST NOT FOUND ERROR";
                            break;
                    }
                }

                response = encryptionHandler.encryptAES(response);
                System.out.println(response);
                break;

            // Unknown state
            default:
                response = "RESPONSE::UNEXPECTED_ERROR";
                break;

        } // end-of-session-key-operation
        out.println(response);
    }

    public String getUserList(){
        String userList = "";
        for(ClientHandler clientHandler : Server.clients){
            if(!clientHandler.username.equalsIgnoreCase(username)){
                userList += clientHandler.username + ",";
            }
        }
        return userList;
    }
}
