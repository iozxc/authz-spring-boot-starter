package cn.omisheep.authz.core.msg;

import cn.omisheep.commons.util.CollectionUtils;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
public class CacheMessage implements Message {
    public static final String CHANNEL = "AU_CACHE_DATA_UPDATE";
    private String id = uuid;
    private Type type;
    private String pattern;
    private Set<String> keys;

    public static CacheMessage write(String key) {
        return single(key).setType(Type.WRITE);
    }

    public static CacheMessage write(String pattern, Collection<String> keys) {
        return collect(keys).setType(Type.WRITE).setPattern(pattern);
    }

    public static CacheMessage delete(String key) {
        return single(key).setType(Type.DELETE);
    }

    public static CacheMessage delete(Collection<String> keys) {
        return collect(keys).setType(Type.DELETE);
    }

    private static CacheMessage collect(Collection<String> keys) {
        CacheMessage message = new CacheMessage();
        if (keys instanceof Set) message.keys = (Set<String>) keys;
        else message.keys = new HashSet<>(keys);
        return message;
    }

    private static CacheMessage single(String key) {
        CacheMessage message = new CacheMessage();
        message.keys = CollectionUtils.singletonSet(key);
        return message;
    }

    public static boolean ignore(CacheMessage message) {
        return message == null || message.id.equals(uuid);
    }

    public enum Type {
        WRITE,
        DELETE,
    }
}
