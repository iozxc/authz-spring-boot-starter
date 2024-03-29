package cn.omisheep.authz.core.msg;

import cn.omisheep.authz.AuthzAutoConfiguration;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.TimeUtils;

/**
 * @author zhouxinchen[1269670415@qq.com]
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
        if (oo == null || !(oo instanceof Message)) return;
        if (oo instanceof CacheMessage) {
            CacheMessage message = (CacheMessage) oo;
            if (!CacheMessage.ignore(message)) {
                LogUtils.debug("MessageReceive time: {} message: {}", TimeUtils.nowTime(), message);
                cache.receive(message);
            }
        } else if (oo instanceof RequestMessage) {
            RequestMessage message = (RequestMessage) oo;
            if (!RequestMessage.ignore(message)) {
                LogUtils.debug("RequestMessage time: {} message: {}", TimeUtils.nowTime(), message);
                Httpd.receive(message);
            }
        } else if (oo instanceof VersionMessage) {
            VersionMessage message = (VersionMessage) oo;
            if (!VersionMessage.ignore(message)) {
                LogUtils.debug("VersionMessage time: {} message: {}", TimeUtils.nowTime(), message);
                AuthzAppVersion.receive(message);
            }
        }
    }
}
