package cn.omisheep.authz.core.cache;

import cn.omisheep.commons.util.CollectionUtils;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 2022-02-02
 */
@Data
@Accessors(chain = true)
public class Message {

    public static final String id = UUID.randomUUID().toString();
    private String uuid = Message.id;
    private MessageType type;
    private String pattern;
    private Set<String> keys;

    public static Message write(String key) {
        return single(key).setType(MessageType.WRITE);
    }

    public static Message write(String pattern, Collection<String> keys) {
        return collect(keys).setType(MessageType.WRITE).setPattern(pattern);
    }

    public static Message delete(String key) {
        return single(key).setType(MessageType.DELETE);
    }

    public static Message delete(Collection<String> keys) {
        return collect(keys).setType(MessageType.DELETE);
    }

    private static Message collect(Collection<String> keys) {
        Message message = new Message();
        if (keys instanceof Set) message.keys = (Set<String>) keys;
        else message.keys = new HashSet<>(keys);
        return message;
    }

    private static Message single(String key) {
        Message message = new Message();
        message.keys = CollectionUtils.singletonSet(key);
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
