import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;

public class MessageReceiver implements Runnable {
    private BufferedReader serverIn;

    public MessageReceiver(BufferedReader serverIn) {
        this.serverIn = serverIn;
    }

    @Override
    public void run() {
        try {
            String serverResponse;
            while ((serverResponse = serverIn.readLine()) != null) {

                // System.out.println("\n********** FROM SERVER **********");
                // System.out.println(serverResponse);

                handleMessage(serverResponse);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Gelen mesajları yöneten fonksiyon
     *
     * @param message
     * @return
     */
    public void handleMessage(String message) throws Exception{
        String[] response;

        switch (Client.clientConnectionState) {

            // sadece PK: varsa çalışır
            case UNSECURE:
            case CONNECTION_PROTOCOL_STEP_1:
                // createSessionKey(message);
                System.out.println("\n********** CLIENT INTERNAL OPS **********");
                if(message.contains("::") && message.split("::").length==2){
                    String serverRequestCommand = message.split("::")[0];
                    if(serverRequestCommand.trim().equalsIgnoreCase("PK")){
                        EncryptionHandler.serverEncodedPublicKey = message.split("::")[1];
                        Client.clientConnectionState = ClientConnectionState.CONNECTION_PROTOCOL_STEP_2;
                        Client.userInputHandler.connectionProtocol();
                    }
                }
                break;

            case SSL_HANDSHAKE:
            case CONNECTION_PROTOCOL_STEP_2:
                response = message.split("::");
                if(response.length==3 && response[0].equalsIgnoreCase("hello") && response[1].equalsIgnoreCase("done")){
                    Client.clientConnectionState = ClientConnectionState.SESSION_KEY;
                    Client.session = response[2];
                }
                break;

            case SESSION_KEY:
            case SECURE_CHAT_PROTOCOL_STEP_1:
                String plainText = EncryptionHandler.decryptAES(Client.sessionKey, message);
                System.out.println(plainText);

                JSONObject jsonObject = tryToGetJsonObject(plainText);
                if(jsonObject!=null){
                    switch (jsonObject.getString("command")){
                        case "chatSessionKey":
                            Client.chatSessionKey = jsonObject.getString("chatSessionKey");
                            Client.chatUserName = jsonObject.getString("username");

                            //Client.clientConnectionState = ClientConnectionState.SESSION_KEY;
                            Client.clientConnectionState = ClientConnectionState.SECURE_CHAT_PROTOCOL_STEP_2;
                            Client.userInputHandler.secureChatProtocol();
                            break;

                        case "sendMessageTo":
                            String encChatMsg = jsonObject.getString("data");
                            printChatMessage(encChatMsg);
                            break;
                    }
                }
                break;

            case SECURE_CHAT_PROTOCOL_STEP_2:
                String encChatMsgFull = EncryptionHandler.decryptAES(Client.sessionKey, message);
                JSONObject chatJson = tryToGetJsonObject(encChatMsgFull);
                if(chatJson!=null){
                    String encChatMsg = chatJson.getString("data");
                    SecretKey chatSessionKey = EncryptionHandler.getAESKey(Client.chatSessionKey);
                    String fromMsg = EncryptionHandler.decryptAES(chatSessionKey, encChatMsg);
                    System.out.println("FROM " + Client.chatUserName + " : " + fromMsg );
                } else {
                    System.out.println("CHAT ERROR ");
                }
                break;
        }
    }

    public void printChatMessage(String serverMessage) throws Exception{
        SecretKey chatSessionKey = EncryptionHandler.getAESKey(Client.chatSessionKey);
        String fromMsg = EncryptionHandler.decryptAES(chatSessionKey, serverMessage);
        System.out.println("FROM " + Client.chatUserName + " : " + fromMsg );
    }

    public JSONObject tryToGetJsonObject(String jsonStr) {
        JSONObject jsonObject = null;
        try {
            jsonObject = new JSONObject(jsonStr);
        } catch (JSONException e){
            // Nothing ...
        }

        return jsonObject;
    }

}