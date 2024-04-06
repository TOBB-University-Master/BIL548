import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.MarkerManager;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;

public class UserInputHandler implements Runnable {
    private BufferedReader userInput;
    private PrintWriter out;
    private EncryptionHandler encryptionHandler;
    private static final Logger logger = LogManager.getLogger();

    public UserInputHandler(BufferedReader userInput, PrintWriter out) {
        this.userInput = userInput;
        this.encryptionHandler = new EncryptionHandler();
    }

    @Override
    public void run() {
        logger.info(MarkerManager.getMarker("START"), "Welcome to secure chat program by YETKY ...");
        try {
            // Start connection protocol
            Client.clientConnectionState = ClientConnectionState.CONNECTION_PROTOCOL_STEP_1;
            connectionProtocol();

            while (true) {
                switch (Client.clientConnectionState) {
                    case SECURE_CHAT_PROTOCOL_STEP_2:
                        secureChatProtocol();
                        break;
                    default:
                        mainMenu();
                        break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
    }


    /**
     * Bu protokol ile Client-Server güvenli bağlantı için anahtar değişimi sağlanır
     */
    public void connectionProtocol() throws Exception{
        logger.info(MarkerManager.getMarker("CONNECTION PROCOTOL V1"), "********** STARTED **********");
        switch (Client.clientConnectionState){
            case CONNECTION_PROTOCOL_STEP_1:
                // SSL/TLS handshake start
                Client.sendMessageToServer("hello::new");
                break;
            case CONNECTION_PROTOCOL_STEP_2:
                System.out.println("Generating session key AES... ");
                Client.sessionKey = EncryptionHandler.generateAESKey(128);
                String AESSessionKeyBase64 = Base64.getEncoder().encodeToString(Client.sessionKey.getEncoded());
                System.out.println("SessionKey::" + AESSessionKeyBase64);
                String encryptedSessionKey = EncryptionHandler.encryptECDH(EncryptionHandler.serverEncodedPublicKey , AESSessionKeyBase64);
                Client.sendMessageToServer(encryptedSessionKey);
                break;
        }
        logger.info(MarkerManager.getMarker("CONNECTION PROCOTOL V1"), "********** FINISHED **********");
    }


    /**
     * Bu protokol ile Client-Server güvenli bağlantı için anahtar değişimi sağlanır
     */
    private void loginProtocol() throws Exception{
        JSONObject requestJsonObj = new JSONObject();
        requestJsonObj.put("command", "login");
        logger.info(MarkerManager.getMarker("LOGIN PROCOTOL V2"), "********** STARTED **********");

        logger.info(MarkerManager.getMarker("WAIT FOR USER INPUT"), "Username: ");
        Client.username = userInput.readLine();
        requestJsonObj.put("username", Client.username);

        logger.info(MarkerManager.getMarker("WAIT FOR USER INPUT"), "Nonce: ");
        Client.nonce = userInput.readLine();
        requestJsonObj.put("nonce", Client.nonce);

        logger.info(MarkerManager.getMarker("SERVER REQUEST"), requestJsonObj.toString());
        logger.info(MarkerManager.getMarker("LOGIN PROCOTOL V2"), "********** FINISHED **********");

        Client.sendMessageToServer(requestJsonObj.toString());
    }


    /**
     *  Bu protokol ile Client-Client arasında anahtar paylaşılarak güvenli sohbet sağlanır
     */
    public void secureChatProtocol() throws Exception{
        JSONObject encJsonData=null;
        JSONObject jsonObject=null;
        switch (Client.clientConnectionState) {

            // select chat key for users
            case SECURE_CHAT_PROTOCOL_STEP_1:

                System.out.println("\n********** SECURE CHAT PROTOCOL STARTED **********");

                encJsonData = new JSONObject();
                System.out.print("Enter username for chat : ");
                String chatUser = userInput.readLine();
                encJsonData.put("from", Client.username);
                encJsonData.put("to", chatUser);
                encJsonData.put("command", "chat");
                encJsonData.put("tgt", Client.TGT);
                encJsonData.put("sa", encryptionHandler.encryptAES(Client.sessionKey, "CRNumber"));

                Client.sendMessageToServer(encJsonData.toString());

                System.out.println("\n********** SECURE CHAT PROCOTOL FINISHED **********");
                break;

            // start chat
            case SECURE_CHAT_PROTOCOL_STEP_2:
                System.out.print("TO " + Client.chatUserName + ": ");
                String textToUser = userInput.readLine();
                encJsonData = new JSONObject();
                encJsonData.put("text", textToUser);

                SecretKey chatSessionKey =  EncryptionHandler.getAESKey(Client.chatSessionKey);
                String encChatMessage = encryptionHandler.encryptAES(chatSessionKey, encJsonData.toString());
                // System.out.println("CHAT SESSION KEY " + Client.chatSessionKey);
                // System.out.println("CHAT ENC " + encChatMessage);

                jsonObject = new JSONObject();
                jsonObject.put("userSession", Client.session);
                jsonObject.put("data", encChatMessage);
                jsonObject.put("command", "sendMessageTo");
                jsonObject.put("to", Client.chatUserName);

                String chatMessage = encryptionHandler.encryptAES(Client.sessionKey, jsonObject.toString());
                Client.sendMessageToServer(chatMessage);
                break;
        }
    }


    /**
     *
     */
    private static void getUserListForChat() throws Exception{
        System.out.println("\n********** USER LIST STARTED **********");

        JSONObject encJsonData = new JSONObject();
        encJsonData.put("command", "user_list");

        String encMessage = EncryptionHandler.encryptAES(Client.sessionKey, encJsonData.toString());
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("from", Client.session);
        jsonObject.put("data", encMessage);
        Client.sendMessageToServer(jsonObject.toString());

        System.out.println("\n********** USER LIST FINISHED **********");
    }

    /**
     * TODO: Silinecek
     *
     * Plaint text göndermek için eklendi...
     *
     * @throws Exception
     */
    public void sendPlainTextToServer() throws Exception{
        System.out.println("\n********** TEST STARTED **********");

        JSONObject encJsonData = new JSONObject();
        encJsonData.put("command", "test");

        String encMessage = EncryptionHandler.encryptAES(Client.sessionKey, encJsonData.toString());
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("from", Client.session);
        jsonObject.put("data", encMessage);
        Client.sendMessageToServer(jsonObject.toString());

        System.out.println("\n********** TEST FINISHED **********");
    }

    private void mainMenu() throws Exception{
        System.out.println("Please choose your action :");
        for(ClientAction clientAction : ClientAction.values()){
            if (clientAction!=ClientAction.NULL)
                System.out.println("\t- " + clientAction.getActionName());
        }

        String command = userInput.readLine();
        ClientAction action = getClientAction(command);

        switch (action){
            case LOGIN:
                loginProtocol();
                break;
            case USER_LIST:
                getUserListForChat();
                break;
            case CHAT:
                Client.clientConnectionState = ClientConnectionState.SECURE_CHAT_PROTOCOL_STEP_1;
                secureChatProtocol();
                break;
            case SEND_MESSAGE:
                // Client.clientConnectionState = ClientConnectionState.SECURE_CHAT_PROTOCOL_STEP_2;
                // secureChatProtocol();

                // TODO: Burada kullanıcı isminin tekrar girilmesine gerek yok
                System.out.print("TO " + Client.chatUserName + ": ");
                String textToUser = userInput.readLine();

                String encChatMessage = encryptionHandler.encryptAES(Client.chatSecretKey, textToUser);

                JSONObject jsonObject = new JSONObject();
                jsonObject.put("msg", encChatMessage);
                jsonObject.put("command", "sendMessage");
                jsonObject.put("to", Client.chatUserName);
                jsonObject.put("from", Client.username);

                Client.sendMessageToServer(jsonObject.toString());

                break;
            case INFO:
                System.out.println("SESSION KEY : " + Base64.getEncoder().encodeToString(Client.sessionKey.getEncoded()));
                System.out.println("CONNECTION STATE : " + Client.clientConnectionState);
                System.out.println("CHAT SESSION KEY : " + Client.chatSessionKey);
                System.out.println("CHAT ACTIVE USER : " + Client.chatUserName);
                break;
            default:
                System.out.println("UNKNOWN COMMAND");
                break;
        }
    }

    private static ClientAction getClientAction(String command) {
        for ( ClientAction action : ClientAction.values()) {
            if (action.getActionName().equals(command)) {
                return action;
            }
        }
        return ClientAction.NULL;
    }

}