package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.AuthzAutoConfiguration;
import cn.omisheep.authz.core.util.LogUtils;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 2022-02-02
 */
@SuppressWarnings("all")
public class MessageReceive {

    private final Cache cache;

    public MessageReceive(Cache cache) {
        this.cache = cache;
    }

    public void handleMessage(String o) {
        Object oo = AuthzAutoConfiguration.CacheAutoConfiguration.jackson2JsonRedisSerializer.deserialize(o.getBytes());
        if (oo == null) return;
        if (oo instanceof Message) {
            Message message = (Message) oo;
            if (!Message.ignore(message)) {
                LogUtils.logDebug("MessageReceive: {}", message);
                cache.receive(message);
            }
        }
    }
}
