import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;
import java.util.List;

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
        this.user.setSession(user.getUsername());
        this.user.setClientConnectionState(ClientConnectionState.UNSECURE);
        this.clientSocket = clientSocket;
        this.encryptionHandler = new EncryptionHandler();
    }

    /**
     * TODO: Burada kalındı...
     *
     * 1- ClientA, ClientB ile sohbet açmak ister
     * 2- Sunucu AES simetrik anahtar oluşturur ve her iki Client'a yollar (chatSessionKey)
     * 3- ClientA ve ClientB için chat state'ine geçilir
     * 4- Chat state'nde ClientA'dan giden mesajlar ClientB'ye chatSessionKey ile şifrelenerek yollanır
     * 5- Sunucu gelen mesajları direk diğer Client'a yollar
     * 6- Chat state'nde Client'a gelen mesajlar chatSessionKey ile deşifre edilir
     * 7- Chat state'inden çıkmak için :exit komutu kullanılabilir
     *
     */
    private void secureChatProtocol(String toUserName) throws Exception{
        // Her iki kullanıcı bulunur
        // Kullanıcılar için ortak anahtar oluşturulur
        String response="ERROR";
        User toUser=null;
        for( User tuser : Server.onlineUserList.values() ){
            if(tuser.getUsername().equalsIgnoreCase(toUserName)){
                toUser = tuser;
            }
        }

        // Chat room oluşturulur
        if(toUser!=null){
            ChatRoom chatRoom = new ChatRoom();
            chatRoom.getUsernameList().add(toUser.getUsername());

            SecretKey secretKey =  EncryptionHandler.generateAESKey(128);
            String AESChatSessionKeyBase64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            chatRoom.setSessionKey(secretKey);

            JSONObject encJsonData = new JSONObject();
            encJsonData.put("chatSessionKey", AESChatSessionKeyBase64);
            encJsonData.put("command", "chatSessionKey");

            // Send chatSessionKey to user1
            encJsonData.put("username", user.getUsername() );
            Server.broadcastTo(toUser.getUsername(), encryptionHandler.encryptAES(toUser.getSessionKey(), encJsonData.toString()));

            // Send chatSessionKey to user2
            encJsonData.put("username", toUser.getUsername() );
            Server.broadcastTo(user.getUsername(), encryptionHandler.encryptAES(user.getSessionKey(), encJsonData.toString()));

        } else {
            response = "USER NOT FOUND";
        }

        response = encryptionHandler.encryptAES(user.getSessionKey() ,response);
        out.println(response);
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
                List<ClientHandler> clientSocketList = Server.clientSocketList;
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

        String response = "RESPONSE:REQUEST FORMAT MUST command::data";
        String command = null;
        String[] request;

        try {
            JSONObject jsonObject = new JSONObject(message);
            String from = jsonObject.getString("from");

            if (from != null) {
                User onlineUser = Server.onlineUserList.get(from);
                if(onlineUser!=null) {
                    user = onlineUser;
                    message = jsonObject.getString("data");
                }
            }
        } catch (JSONException e){
            // Nothing ...
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
                if(Server.onlineUserList.get(user.getSession())==null){
                    Server.onlineUserList.putIfAbsent( user.getSession(), user);
                }
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
                            secureChatProtocol(jsonObject.getString("username"));
                            break;

                        case "sendMessageTo":
                            String to = jsonObject.getString("to");
                            String data = jsonObject.getString("data");

                            // TODO: Neden istenilen clientHandler'a gitmiyor ?
                            System.out.println(jsonObject.getString("data"));
                            Server.broadcastToEnc(to,plainText);
                            //Server.broadcastEnc(data);

                            break;

                        /**
                         * TODO: Silinecek
                         *
                         * Plain text göndermek için eklendi...
                         */
                        case "test":
                            Server.broadcastToEnc("sami","testasdasds");
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
        for(User onlineUserList : Server.onlineUserList.values()){
            if(!onlineUserList.getUsername().equalsIgnoreCase(user.getUsername()) &&
                    onlineUserList.getRole()==UserRole.USER){
                userList += onlineUserList.getUsername() + ",";
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
