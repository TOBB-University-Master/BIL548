import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientHandler implements Runnable {

    // Client
    public User user;
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;

    private EncryptionHandler encryptionHandler;

    public ClientHandler(Socket clientSocket) {
        this.user = new User();
        this.user.setId(""+ ((int)(Math.random() * (100000) + 1)));
        this.user.setUsername("user_" + this.user.getId() );
        this.user.setClientConnectionState(ClientConnectionState.UNSECURE);
        this.clientSocket = clientSocket;
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

        try {
            JSONObject jsonObject = new JSONObject(message);
            String from = jsonObject.getString("from");

            // TODO: Kullanıcı listede ise anahtarı alınarak login işlemine başlanır
            if (from != null) {
                for(User onlineUser :Server.onlineUserList){
                    if(onlineUser.getUsername().equalsIgnoreCase(from)){
                        user = onlineUser;
                        message = jsonObject.getString("data");
                        break;
                    }
                }
            }
        } catch (JSONException e){
            System.out.println("SİLİNECEK: STR TO JSON OBJECT DEVAM ET...");
        }


        switch (user.getClientConnectionState()) {

            // Public key send to client
            case UNSECURE:
                request = message.split("::");
                if(request!=null && request.length>0){
                    command = request[0];
                    if(command.equalsIgnoreCase("hello")){
                        response = "PK::" + Server.publicKeyEncoded;
                        user.setClientConnectionState(ClientConnectionState.SSL_HANDSHAKE_START);
                    }
                }
                break;

            case SSL_HANDSHAKE_START:
                String sessionKey = EncryptionHandler.decryptECDH(message);
                System.out.println("Session Key : " + sessionKey);
                user.setClientConnectionState(ClientConnectionState.SESSION_KEY);
                user.setSessionKey(encryptionHandler.getAESKey(sessionKey));
                Server.onlineUserList.add(user);
                response = "hello::done::"+user.getUsername();
                break;

            // All messages will be encrypted
            case SESSION_KEY:
                String plainText = encryptionHandler.decryptAES(user.getSessionKey() ,message);
                System.out.println("PLAIN TEXT : " + plainText);
                JSONObject jsonObject = getJsonObject(plainText);
                if(jsonObject!=null){
                    switch (jsonObject.getString("command")){

                        case "login":
                            String username = jsonObject.getString("username");
                            String password = jsonObject.getString("password");

                            User userInDB = Server.userDatabase.get(username);
                            if(userInDB==null){
                                response = "RESPONSE::USER_NOT_FOUND";
                            } else if(!userInDB.getPassword().equalsIgnoreCase(password)){
                                response = "RESPONSE::USER_PASSWORD_WRONG";
                            } else {
                                user.setId(userInDB.getId());
                                user.setUsername(userInDB.getUsername());
                                user.setRole(UserRole.USER);
                                // TODO: Aynı hesapla birden fazla giriş için username yerine tekil id'lerle tutulabilir...
                                response = "login::done";
                            }
                            break;

                        case "user_list":
                            response = getUserList();
                            System.out.println(response);
                            break;

                        case "chat":
                            /*
                            if(request.length==4){
                                String userPK = request[2];
                                String username = request[3];
                                response = "chat::new::" + userPK + "::" + user.getUsername();

                            } else {
                                response = "RESPONSE::PARAMETER_ERROR";
                            }
                             */
                            break;

                        default:
                            response = "RESPONSE: REQUEST NOT FOUND ERROR";
                            break;
                    }
                }

                response = encryptionHandler.encryptAES(user.getSessionKey() ,response);
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
            if(!clientHandler.user.getUsername().equalsIgnoreCase(user.getUsername())){
                userList += clientHandler.user.getUsername() + ",";
            }
        }
        return userList;
    }

    public JSONObject getJsonObject(String jsonStr) {
        JSONObject jsonObject = null;
        try {
            jsonObject = new JSONObject(jsonStr);
        } catch (JSONException e){}

        return jsonObject;
    }
}
