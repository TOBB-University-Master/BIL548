public enum ClientAction {

    LOGIN("login"),
    USER_LIST("available_user_for_chat"),
    CHAT("chat"),
    SEND_MESSAGE("send_message"),
    INFO("info"),
    NULL("");

    private String action;

    ClientAction(String envUrl) {
        this.action = envUrl;
    }

    public String getActionName() {
        return action;
    }

}
