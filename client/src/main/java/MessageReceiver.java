import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.MarkerManager;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;

/**
 * Client'a gelen mesajları handle eden thread
 */
public class MessageReceiver implements Runnable {
    private BufferedReader serverIn;
    private static final Logger logger = LogManager.getLogger();

    public MessageReceiver(BufferedReader serverIn) {
        this.serverIn = serverIn;
    }

    @Override
    public void run() {
        logger.info(MarkerManager.getMarker("START"), "Ready for incoming messages...");
        try {
            String serverResponse;
            while ((serverResponse = serverIn.readLine()) != null) {
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
        logger.info(MarkerManager.getMarker("INCOMING MESSAGE") , message);
        String[] response;
        String plainText = "";

        exitMain:
        switch (Client.clientConnectionState) {

            // sadece PK: varsa çalışır
            case UNSECURE:
            case CONNECTION_PROTOCOL_STEP_1:
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

                // TRY TO DECRYPT WITH LONG TERM KEY
                try{

                    // Client.longTermSecretKey = EncryptionHandler.getAESKey("12345");
                    //plainText = EncryptionHandler.decryptAES(Client.longTermSecretKey, message);

                    String privateKey =  Client.userPrivateKeyList.get(Client.username);
                    plainText = EncryptionHandler.decryptECDH(privateKey, message);

                    logger.info(MarkerManager.getMarker("LONG-TERM KEY DEC") , plainText);

                    JSONObject jsonObject = tryToGetJsonObject(plainText);
                    if(jsonObject!=null){
                        if(Client.nonce.equalsIgnoreCase(jsonObject.getString("nonce"))){
                            logger.info(MarkerManager.getMarker("LOGIN NONCE MATCH") , "Client nonce:" + Client.nonce + " - " + " Server nonce:" + jsonObject.getString("nonce"));
                            Client.sessionKey = EncryptionHandler.getAESKey(jsonObject.getString("session"));
                            Client.TGT = jsonObject.getString("tgt");
                            Client.sessionTimestamp = jsonObject.getString("timestamp");

                            JSONObject encJsonData = new JSONObject();
                            encJsonData.put("tgt", Client.TGT);
                            encJsonData.put("sa", EncryptionHandler.encryptAES( Client.sessionKey , Client.sessionTimestamp));
                            encJsonData.put("command", "login_final");

                            Client.sendMessageToServer(encJsonData.toString());

                        } else {
                            logger.error(MarkerManager.getMarker("LOGIN NONCE ERROR") , Client.nonce + " != " + jsonObject.getString("nonce"));
                        }
                    }

                    break exitMain;
                } catch (Exception e){
                    plainText = message; // continue;
                }

                // TRY TO DECRYPT WITH SHORT TERM KEY (SESSION)
                try{
                    plainText = EncryptionHandler.decryptAES(Client.sessionKey, message);
                    logger.info(MarkerManager.getMarker("SHORT-TERM KEY DEC") , plainText);

                    JSONObject jsonObject = tryToGetJsonObject(plainText);
                    if(jsonObject!=null){
                        Client.chatState = jsonObject.getString("state");
                        if(Client.chatState.equalsIgnoreCase("initial")){

                            Client.chatSecretKey = EncryptionHandler.getAESKey(jsonObject.getString("chatkey"));
                            Client.chatUserName = jsonObject.getString("to");

                            // Send ticket to Bob
                            JSONObject encJsonData = new JSONObject();
                            Client.aliceBobCR = "dummyKABValueForTicketBChallengeResponse";
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

                // Long term & short term key cannot decrypt incoming message so continue as plain
                JSONObject jsonObject = tryToGetJsonObject(plainText);
                if(jsonObject!=null){
                    switch (jsonObject.getString("command")){
                        case "login":
                            logger.info(MarkerManager.getMarker("LOGIN STATUS") , jsonObject.getString("status"));
                            break;

                        case "sendTicketToBob":
                            // KAB değeri varsa decrypt edilmesi gerekir
                            String kabCRNonce;
                            try{
                                kabCRNonce = EncryptionHandler.decryptAES(Client.chatSecretKey, jsonObject.getString("kab"));
                                if(kabCRNonce.equalsIgnoreCase(Client.aliceBobCR+"-1")){
                                    logger.info(MarkerManager.getMarker("CHAT STATUS READY") , "**********" + " Server Nonce:" + Client.aliceBobCR + " Incoming CRNonce:" + kabCRNonce);
                                    break exitMain;
                                }
                            } catch (Exception e){}

                            // Decrypt ticket
                            String ticketB = jsonObject.getString("ticketB");
                            ticketB = EncryptionHandler.decryptAES(Client.sessionKey, ticketB);
                            JSONObject ticketJson = new JSONObject(ticketB);
                            Client.chatSecretKey =  EncryptionHandler.getAESKey(ticketJson.getString("chatkey"));
                            Client.chatUserName = ticketJson.getString("to");
                            logger.info(MarkerManager.getMarker("TICKET PLAIN") , ticketB);

                            // Decrypt KAB nonce
                            kabCRNonce = EncryptionHandler.decryptAES(Client.chatSecretKey, jsonObject.getString("kab"));
                            logger.info(MarkerManager.getMarker("KAB PLAIN") , kabCRNonce);

                            // Send Challange Response value To Alice
                            JSONObject encJsonData = new JSONObject();
                            encJsonData.put("kab", EncryptionHandler.encryptAES( Client.chatSecretKey , kabCRNonce + "-1"));
                            encJsonData.put("to", ticketJson.getString("to"));
                            encJsonData.put("command", "sendTicketToBob");
                            Client.sendMessageToServer(encJsonData.toString());

                            break;

                        case "sendMessage":
                            // Gelen mesajın MAC'i kontrol edilir
                            String macResult = EncryptionHandler.getTextMAC(Client.chatSecretKey, jsonObject.getString("msg"));
                            if(macResult.equalsIgnoreCase(jsonObject.getString("mac"))){
                                String msg = EncryptionHandler.decryptAES(Client.chatSecretKey, jsonObject.getString("msg"));
                                logger.info(MarkerManager.getMarker("MAC SUCCESS" ) , "Incoming Message MAC:" + jsonObject.getString("mac") + " - " + " Client Calculated MAC:" + macResult);
                                logger.warn(MarkerManager.getMarker("FROM " + jsonObject.getString("from")) , msg);
                            } else {
                                logger.error(MarkerManager.getMarker("MAC ERROR") , "MAC NOT MATCH");
                            }

                            break;

                        case "chatSessionKey":
                            Client.chatSessionKey = jsonObject.getString("chatSessionKey");
                            Client.chatUserName = jsonObject.getString("username");
                            logger.info(MarkerManager.getMarker("CHAT STATUS") , "********** READY FOR CHAT **********");
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