import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

@Data
@AllArgsConstructor
public class ChatRoom {

    private int id;
    private HashSet<String> usernameList=new HashSet<>();
    private SecretKey sessionKey=null;
    private List<Message> messageList=new ArrayList<>();

    public ChatRoom(){
        this.id = (int)(Math.random() * (1000000));
    }
}
