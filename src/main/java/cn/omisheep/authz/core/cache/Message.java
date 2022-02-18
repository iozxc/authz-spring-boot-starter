package cn.omisheep.authz.core.cache;

import cn.omisheep.commons.util.CollectionUtils;
import lombok.Data;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 2022-02-02
 */
@Data
public class Message {

    public static final String id = UUID.randomUUID().toString();
    private String uuid = Message.id;

    /**
     * update
     */
    private MessageType type;

    /**
     * write is singleton
     * <p>
     * delete is list
     */
    private Set<String> keys;


    public static Message write(String key) {
        Message message = new Message();
        message.type = MessageType.WRITE;
        message.keys = CollectionUtils.singletonSet(key);
        return message;
    }

    public static Message delete(String key) {
        Message message = new Message();
        message.type = MessageType.DELETE;
        message.keys = CollectionUtils.singletonSet(key);
        return message;
    }

    public static Message delete(Collection<String> keys) {
        Message message = new Message();
        message.type = MessageType.DELETE;
        if (keys instanceof Set) message.keys = (Set<String>) keys;
        else message.keys = new HashSet<>(keys);
        return message;
    }


    public enum MessageType {
        WRITE,
        DELETE,
    }

    public static boolean ignore(Message message) {
        return message == null || message.getUuid().equals(id);
    }

}
