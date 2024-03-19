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

    public UserInputHandler(BufferedReader userInput, PrintWriter out) {
        this.userInput = userInput;
        this.encryptionHandler = new EncryptionHandler();
    }

    @Override
    public void run() {
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
        System.out.println("\n********** CONNECTION PROCOTOL STARTED **********");
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
        System.out.println("\n********** CONNECTION PROCOTOL FINISHED **********");
    }


    /**
     * Bu protokol ile Client-Server güvenli bağlantı için anahtar değişimi sağlanır
     */
    private void loginProtocol() throws Exception{
        System.out.println("\n********** LOGIN PROCOTOL STARTED **********");

        /**
         * Simetrik anahtar ile kullanıcı login olur
         */
        JSONObject encJsonData = new JSONObject();
        System.out.print("Username: ");
        String username = userInput.readLine();
        encJsonData.put("username", username);
        System.out.print("Password: ");
        String password = userInput.readLine();
        encJsonData.put("password", password);
        encJsonData.put("command", "login");

        String encMessage = encryptionHandler.encryptAES( Client.sessionKey , encJsonData.toString());
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("from", Client.session);
        jsonObject.put("data", encMessage);
        Client.sendMessageToServer(jsonObject.toString());

        System.out.println("\n********** LOGIN PROCOTOL FINISHED **********");
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
                System.out.print("Enter username for chat without , : ");
                String username = userInput.readLine();
                encJsonData.put("username", username);
                encJsonData.put("command", "chat");

                String encMessage = encryptionHandler.encryptAES(Client.sessionKey, encJsonData.toString());
                jsonObject = new JSONObject();
                jsonObject.put("from", Client.session);
                jsonObject.put("data", encMessage);
                Client.sendMessageToServer(jsonObject.toString());

                System.out.println("\n********** SECURE CHAT PROCOTOL FINISHED **********");
                break;

            // start chat
            case SECURE_CHAT_PROTOCOL_STEP_2:
                userInput.reset();
                System.out.print("TO " + Client.chatUserName + ": ");
                String textToUser = userInput.readLine();
                encJsonData = new JSONObject();
                encJsonData.put("text", textToUser);

                // TODO: gelen chat session key
                SecretKey chatSessionKey =  EncryptionHandler.getAESKey(Client.chatSessionKey);
                String encChatMessage = encryptionHandler.encryptAES(chatSessionKey, encJsonData.toString());
                System.out.println("CHAT SESSION KEY " + Client.chatSessionKey);
                System.out.println("CHAT ENC " + encChatMessage);

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
        System.out.print("Komut girin (login, user_list, chat, start_chat, show_chat_key, show_chat_user): ");
        String command = userInput.readLine();

        if (command.equals("login")) {
            loginProtocol();

        } else if (command.equals("user_list")) {
            getUserListForChat();

        } else if (command.equals("chat")) {
            Client.clientConnectionState = ClientConnectionState.SECURE_CHAT_PROTOCOL_STEP_1;
            secureChatProtocol();

        } else if (command.equals("start_chat")) {
            Client.clientConnectionState = ClientConnectionState.SECURE_CHAT_PROTOCOL_STEP_2;
            secureChatProtocol();

        } else if (command.equals("show_chat_key")) {
            System.out.println(Client.chatSessionKey);

        } else if (command.equals("show_chat_user")) {
            System.out.println(Client.chatUserName);

        } else if (command.equals("test")) {
            sendPlainTextToServer();

        } else if (command.equals("test_enc")) {

            System.out.print("Enter AES :");
            String aesStr = userInput.readLine();

            System.out.print("Enter Enc :");
            String encChatMessage = userInput.readLine();

            // TODO: gelen chat session key
            SecretKey chatSessionKey =  EncryptionHandler.getAESKey(aesStr);
            String chatMessage = EncryptionHandler.decryptAES(chatSessionKey, encChatMessage);
            System.out.println("CHAT MSG " + chatMessage);

        } else if (command.equals("exit")) {
            System.out.println("Programdan çıkılıyor...");

        } else {
            System.out.println("Geçersiz komut!");
        }
    }

}