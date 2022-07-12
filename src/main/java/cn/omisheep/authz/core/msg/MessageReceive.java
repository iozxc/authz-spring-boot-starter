package cn.omisheep.authz.core.msg;

import cn.omisheep.authz.AuthzAutoConfiguration;
import cn.omisheep.authz.core.config.InfoVersion;
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
    private final Httpd httpd;

    public MessageReceive(Cache cache, Httpd httpd) {
        this.cache = cache;
        this.httpd = httpd;
    }

    public void handleMessage(String o) {
        Object oo = AuthzAutoConfiguration.CacheAutoConfiguration.jackson2JsonRedisSerializer.deserialize(o.getBytes());
        if (oo == null || !(oo instanceof Message)) return;
        if (oo instanceof CacheMessage) {
            CacheMessage message = (CacheMessage) oo;
            if (!CacheMessage.ignore(message)) {
                LogUtils.logDebug("MessageReceive time: {} message: {}", TimeUtils.nowTime(), message);
                cache.receive(message);
            }
        } else if (oo instanceof RequestMessage) {
            RequestMessage message = (RequestMessage) oo;
            if (!RequestMessage.ignore(message)) {
                LogUtils.logDebug("RequestMessage time: {} message: {}", TimeUtils.nowTime(), message);
                httpd.receive(message);
            }
        } else if (oo instanceof VersionMessage) {
            VersionMessage message = (VersionMessage) oo;
            if (!VersionMessage.ignore(message)) {
                LogUtils.logDebug("VersionMessage time: {} message: {}", TimeUtils.nowTime(), message);
                InfoVersion.receive(message);
            }
        }
    }
}
