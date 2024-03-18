import java.io.BufferedReader;
import java.io.IOException;
import java.util.Base64;

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
    public String handleMessage(String message) throws Exception{
        String command = null;
        String[] response;
        switch (Client.clientConnectionState) {

            // sadece PK: varsa çalışır
            case UNSECURE:
                createSessionKey(message);
                break;

            case SSL_HANDSHAKE:
                if(message.equalsIgnoreCase("hello::done")){
                    Client.clientConnectionState = ClientConnectionState.SESSION_KEY;
                }
                break;

            case SESSION_KEY:
                String plainText = EncryptionHandler.decryptAES(message);
                System.out.println(plainText);
                break;
        }
        return "";
    }

    /**
     * Sunucudan gelen mesaj PK::MFkwEwY... formatında ise session key olarak AES anahtar oluştur
     *
     * @param serverMsg
     */
    private void createSessionKey(String serverMsg){
        System.out.println("\n********** CLIENT INTERNAL OPS **********");
        if(serverMsg.contains("::") && serverMsg.split("::").length==2){
            String serverRequestCommand = serverMsg.split("::")[0];
            String serverRequestData = serverMsg.split("::")[1];
            if(serverRequestCommand.trim().equalsIgnoreCase("PK")){
                System.out.println("Generating session key AES... ");
                try{
                    EncryptionHandler.generateAESKey(128);
                    String AESSessionKeyBase64 = Base64.getEncoder().encodeToString(EncryptionHandler.sessionKey.getEncoded());
                    System.out.println("SessionKey::" + AESSessionKeyBase64);
                    String encryptedSessionKey = EncryptionHandler.encryptECDH(serverRequestData , AESSessionKeyBase64);
                    Client.clientConnectionState = ClientConnectionState.SSL_HANDSHAKE;
                    //sendMessage(encryptedSessionKey);
                }catch (Exception e){
                    e.printStackTrace();
                }

            }
        }
    }
}