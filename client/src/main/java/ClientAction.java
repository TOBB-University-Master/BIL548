public enum ClientAction {

    LOGIN("login"),
    USER_LIST("available_user_for_chat"),
    CHAT("chat"),
    START_CHAT("start_chat"),
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
