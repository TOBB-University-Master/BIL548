import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.crypto.SecretKey;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {

    private String id;
    private String username;
    private String password;
    private UserRole role = UserRole.ANONYMOUS;
    private SecretKey sessionKey=null;
    private ClientConnectionState clientConnectionState = ClientConnectionState.UNSECURE;

    public User(String username , SecretKey sessionKey){
        this.username = username;
        this.sessionKey = sessionKey;
    }

    public User(String id, String name, String password) {
        this.id = id;
        this.username = name;
        this.password = password;
    }
}
