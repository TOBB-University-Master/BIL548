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

        exitMain:
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
                // TODO: Kullanıcı parolası herkesin 12345 şimdilik
                System.out.println("Message :: " + message);
                String plainText = "";

                // TRY TO DECRYPT WITH LONG TERM KEY
                try{
                    // 12345 user password
                    Client.longTermSecretKey = EncryptionHandler.getAESKey("12345");
                    plainText = EncryptionHandler.decryptAES(Client.longTermSecretKey, message);
                    System.out.println(plainText);

                    JSONObject jsonObject = tryToGetJsonObject(plainText);
                    if(jsonObject!=null){
                        if(Client.nonce.equalsIgnoreCase(jsonObject.getString("nonce"))){
                            Client.sessionKey = EncryptionHandler.getAESKey(jsonObject.getString("session"));
                            Client.TGT = jsonObject.getString("tgt");
                            Client.sessionTimestamp = jsonObject.getString("timestamp");

                            JSONObject encJsonData = new JSONObject();
                            encJsonData.put("tgt", Client.TGT);
                            encJsonData.put("sa", EncryptionHandler.encryptAES( Client.sessionKey , Client.sessionTimestamp));
                            encJsonData.put("command", "login_final");

                            Client.sendMessageToServer(encJsonData.toString());

                        } else {
                            System.out.println("NONCE HATASI...");
                        }
                    }

                    System.out.println("SECURE_CHAT_PROTOCOL_STEP_1 EXIT#1...");
                    break exitMain;
                } catch (Exception e){
                    // continue;
                    plainText = message;
                }

                // TRY TO DECRYPT WITH SHORT TERM KEY (SESSION)
                try{
                    plainText = EncryptionHandler.decryptAES(Client.sessionKey, message);
                    System.out.println(plainText);

                    JSONObject jsonObject = tryToGetJsonObject(plainText);
                    if(jsonObject!=null){
                        Client.chatState = jsonObject.getString("state");
                        if(Client.chatState.equalsIgnoreCase("initial")){

                            Client.chatSecretKey = EncryptionHandler.getAESKey(jsonObject.getString("chatkey"));
                            Client.chatUserName = jsonObject.getString("to");

                            // Send ticket to Bob
                            JSONObject encJsonData = new JSONObject();
                            Client.aliceBobCR = "challengeResponseForChat";
                            encJsonData.put("kab", EncryptionHandler.encryptAES( Client.chatSecretKey , Client.aliceBobCR));
                            encJsonData.put("to", jsonObject.getString("to"));
                            encJsonData.put("ticketB", jsonObject.getString("ticketb"));
                            encJsonData.put("command", "sendTicketToBob");
                            Client.sendMessageToServer(encJsonData.toString());
                        }
                    }

                    break exitMain;
                } catch (Exception e){
                    plainText = message;
                }


                // TRY TO
                System.out.println(plainText);
                JSONObject jsonObject = tryToGetJsonObject(plainText);
                if(jsonObject!=null){
                    switch (jsonObject.getString("command")){
                        case "login":
                            System.out.println("LOGIN STATUS :: " + jsonObject.getString("status"));
                            break;

                        case "sendTicketToBob":

                            // KAB değeri varsa decrypt edilmesi gerekir
                            String kabCRNonce;
                            try{
                                kabCRNonce = EncryptionHandler.decryptAES(Client.chatSecretKey, jsonObject.getString("kab"));
                                if(kabCRNonce.equalsIgnoreCase(Client.aliceBobCR+"-1")){
                                    System.out.println("\n********** READY FOR CHAT **********");
                                    break exitMain;
                                }
                            } catch (Exception e){}

                            // Decrypt ticket
                            String ticketB = jsonObject.getString("ticketB");
                            ticketB = EncryptionHandler.decryptAES(Client.sessionKey, ticketB);
                            JSONObject ticketJson = new JSONObject(ticketB);
                            Client.chatSecretKey =  EncryptionHandler.getAESKey(ticketJson.getString("chatkey"));
                            Client.chatUserName = ticketJson.getString("to");
                            System.out.println("TICKET PLAIN::" + ticketB);

                            // Decrypt KAB nonce
                            kabCRNonce = EncryptionHandler.decryptAES(Client.chatSecretKey, jsonObject.getString("kab"));
                            System.out.println("KAB PLAIN::" + kabCRNonce);

                            // Send Challange Response value To Alice
                            JSONObject encJsonData = new JSONObject();
                            encJsonData.put("kab", EncryptionHandler.encryptAES( Client.chatSecretKey , kabCRNonce + "-1"));
                            encJsonData.put("to", ticketJson.getString("to"));
                            encJsonData.put("command", "sendTicketToBob");
                            Client.sendMessageToServer(encJsonData.toString());

                            break;

                        case "sendMessage":
                            String msg = EncryptionHandler.decryptAES(Client.chatSecretKey, jsonObject.getString("msg"));
                            System.out.println("---------------------");
                            System.out.println("FROM " + jsonObject.getString("from"));
                            System.out.println(msg);
                            System.out.println("---------------------");
                            break;

                        case "chatSessionKey":
                            Client.chatSessionKey = jsonObject.getString("chatSessionKey");
                            Client.chatUserName = jsonObject.getString("username");
                            System.out.println("\n********** READY FOR CHAT **********");

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