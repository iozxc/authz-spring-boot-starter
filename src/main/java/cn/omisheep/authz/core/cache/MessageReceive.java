package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.AuthzAutoConfiguration;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.TimeUtils;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
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
                LogUtils.logDebug("MessageReceive time: {} message: {}", TimeUtils.nowTime(), message);
                cache.receive(message);
            }
            return;
        }
        if (oo instanceof RequestMessage) {
            RequestMessage message = (RequestMessage) oo;
            LogUtils.logDebug("MessageReceive time: {} message: {}", TimeUtils.nowTime(), message);
        }
    }
}
