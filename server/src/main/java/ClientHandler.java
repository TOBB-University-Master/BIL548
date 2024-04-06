import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class ClientHandler implements Runnable {

    // Client
    public User user;
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private String session;
    private EncryptionHandler encryptionHandler;
    private static final Logger logger = LogManager.getLogger(ClientHandler.class);

    private static final Marker CLIENT_REQUEST = MarkerManager.getMarker("CLIENT REQUEST");
    private static final Marker CLIENT_RESPONSE = MarkerManager.getMarker("CLIENT RESPONSE");

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
        logger.info(CLIENT_REQUEST , "CLIENT REQUEST :: " + message);

        String response = "RESPONSE:REQUEST FORMAT MUST JSON FORMAT";
        JSONObject responseJsonObject = new JSONObject();
        responseJsonObject.put("status" , "start");
        String command = null;
        String[] request;
        String plainText = "";

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
                logger.info(CLIENT_REQUEST , ClientConnectionState.SSL_HANDSHAKE_START.name() +  " :: SESSION KEY :: " + sessionKey);
                user.setClientConnectionState(ClientConnectionState.SESSION_KEY);
                user.setSessionKey(encryptionHandler.getAESKey(sessionKey));
                if(Server.onlineUserList.get(user.getSession())==null){
                    Server.onlineUserList.putIfAbsent( user.getSession(), user);
                }
                response = "hello::done::"+user.getUsername();
                break;


            case SESSION_KEY:
                plainText = message;
                JSONObject jsonObject = getJsonObject(plainText);
                if(jsonObject!=null){
                    switch (jsonObject.getString("command")){

                        case "login":
                            logger.info(MarkerManager.getMarker("LOGIN"), "********** START **********");
                            String username = jsonObject.getString("username");
                            String nonce = jsonObject.getString("nonce");

                            User userInDB = Server.userDatabase.get(username);
                            if(userInDB==null){
                                response = "RESPONSE::USER_NOT_FOUND";
                                responseJsonObject.put("status" , "error");
                                responseJsonObject.put("statusMsg" , "user not found");
                            } else {
                                user.setId(userInDB.getId());
                                user.setUsername(userInDB.getUsername());
                                user.setRole(UserRole.USER);

                                // Generate Security Associations
                                session = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 30);        // random 30 length word
                                userInDB.setSessionKey(encryptionHandler.getAESKey(session));
                                userInDB.setSession(session);
                                Timestamp timestamp = new Timestamp(System.currentTimeMillis());

                                JSONObject tgtJsonData = new JSONObject();
                                tgtJsonData.put("user", userInDB.getUsername());
                                tgtJsonData.put("session", session);
                                tgtJsonData.put("timestamp", timestamp.toString());
                                SecretKey privateKey = encryptionHandler.getAESKey(Server.SERVER_PRIVATE_KEY);
                                String __TGT__ = EncryptionHandler.encryptAES(privateKey, tgtJsonData.toString());

                                JSONObject encJsonData = new JSONObject();
                                encJsonData.put("session", session);
                                encJsonData.put("tgt", __TGT__);
                                encJsonData.put("nonce", nonce);
                                encJsonData.put("timestamp", timestamp.toString());
                                logger.info(MarkerManager.getMarker("LOGIN PLAIN TEXT"), encJsonData.toString());

                                //TODO: AES yerine public key kullanılacak
                                //SecretKey secretKey = encryptionHandler.getAESKey(userInDB.getPassword());
                                //String encryptedText = EncryptionHandler.encryptAES(secretKey, encJsonData.toString());

                                String encryptedText = EncryptionHandler.encryptECDH(userInDB.getPassword(), encJsonData.toString());

                                logger.info(MarkerManager.getMarker("LOGIN ENC TEXT"), encryptedText);
                                response = encryptedText;
                            }

                            logger.info(MarkerManager.getMarker("LOGIN"), "********** C&R **********");
                            break;

                        case "login_final":
                            JSONObject responseJson = new JSONObject();
                            String TGTEncrypted = jsonObject.getString("tgt");
                            String SAEncrypted = jsonObject.getString("sa");
                            logger.info(MarkerManager.getMarker("LOGIN TGT ENCRYPTED"), TGTEncrypted);

                            String TGTPlain = encryptionHandler.decryptAES(encryptionHandler.getAESKey(Server.SERVER_PRIVATE_KEY),TGTEncrypted);
                            logger.info(MarkerManager.getMarker("LOGIN TGT PLAIN"), TGTPlain);

                            JSONObject TGTJsonObject = new JSONObject(TGTPlain);
                            String sessionKeyForDecryption = TGTJsonObject.getString("session");
                            String SAPlain = encryptionHandler.decryptAES(encryptionHandler.getAESKey(sessionKeyForDecryption),SAEncrypted);

                            logger.info(MarkerManager.getMarker("LOGIN SA ENCRYPTED"), SAEncrypted);
                            logger.info(MarkerManager.getMarker("LOGIN SA PLAIN"), SAPlain);

                            responseJson.put("command" , "login");
                            if(SAPlain.equalsIgnoreCase(TGTJsonObject.getString("timestamp"))){
                                responseJson.put("status" , "success");
                            } else {
                                responseJson.put("status" , "failure");
                            }

                            response = responseJson.toString();
                            break ;

                        case "user_list":
                            response = getUserList();
                            System.out.println(response);
                            break;

                        case "chat":
                            logger.info(MarkerManager.getMarker("CHAT"), "********** START **********");
                            String chatFromUser = jsonObject.getString("from");
                            String chatToUser = jsonObject.getString("to");
                            String chatTGTEncrypted = jsonObject.getString("tgt");
                            String chatSAEncrypted = jsonObject.getString("sa");

                            User chatUserInDB = Server.userDatabase.get(chatToUser);
                            if(chatUserInDB==null){
                                response = "RESPONSE::USER_NOT_FOUND";
                            } else {

                                String chatTGTPlain = encryptionHandler.decryptAES(encryptionHandler.getAESKey(Server.SERVER_PRIVATE_KEY),chatTGTEncrypted);
                                logger.info(MarkerManager.getMarker("CHAT TGT ENCRYPTED"), chatTGTEncrypted);
                                logger.info(MarkerManager.getMarker("CHAT TGT PLAIN"), chatTGTPlain);

                                JSONObject chatTGTJsonObject = new JSONObject(chatTGTPlain);
                                String chatSessionKeyForDecryption = chatTGTJsonObject.getString("session");

                                String chatSAPlain = encryptionHandler.decryptAES(encryptionHandler.getAESKey(chatSessionKeyForDecryption),chatSAEncrypted);
                                String chatKey = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 30);        // random 30 length word

                                logger.info(MarkerManager.getMarker("CHAT SA PLAIN"), chatSAPlain);
                                logger.info(MarkerManager.getMarker("CHAT GENERATE KAB"), chatKey);

                                JSONObject ticketBJson = new JSONObject();
                                ticketBJson.put("to", chatFromUser);
                                ticketBJson.put("chatkey", chatKey);
                                ticketBJson.put("state", "initial");
                                // Encrypt ticket by Bob's key
                                String ticketEncryptedText = EncryptionHandler.encryptAES(chatUserInDB.getSessionKey(), ticketBJson.toString());

                                logger.info(MarkerManager.getMarker("CHAT TICKETB PLAIN"), ticketBJson.toString());
                                logger.info(MarkerManager.getMarker("CHAT TICKETB ENCRYPTED"), ticketEncryptedText);
                                logger.info(MarkerManager.getMarker("CHAT TICKETB OWNER"), chatUserInDB.getUsername());


                                JSONObject encJsonData = new JSONObject();
                                encJsonData.put("to", chatToUser);
                                encJsonData.put("chatkey", chatKey);
                                encJsonData.put("state", "initial");
                                encJsonData.put("ticketb", ticketEncryptedText);
                                encJsonData.put("nonce", chatSAPlain);
                                logger.info(MarkerManager.getMarker("CHAT RESPONSE PLAIN"), encJsonData.toString());

                                // SessionA ile encrypt edilir
                                response = EncryptionHandler.encryptAES(encryptionHandler.getAESKey(chatSessionKeyForDecryption), encJsonData.toString());
                            }
                            break;


                        case "sendTicketToBob":
                            // TODO: Logger eklenecek kimden kime proxy edildigi
                            String sendToTicketUser = jsonObject.getString("to");
                            Server.broadcastTo(sendToTicketUser,plainText);
                            break;

                        case "sendMessage":
                            // TODO: Logger eklenecek kimden kime proxy edildigi
                            Server.broadcastTo(jsonObject.getString("to"),plainText);
                            break;

                        case "sendMessageTo":
                            Server.broadcastToEnc(jsonObject.getString("to"),plainText);
                            break;

                        default:
                            response = "RESPONSE: REQUEST NOT FOUND ERROR";
                            break;
                    }
                }

                break;

            // Unknown state
            default:
                response = "RESPONSE::UNEXPECTED_ERROR";
                break;

        } // end-of-session-key-operation

        logger.info(CLIENT_RESPONSE, response);
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
