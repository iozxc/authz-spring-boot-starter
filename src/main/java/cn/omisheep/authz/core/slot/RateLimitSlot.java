package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import cn.omisheep.authz.core.auth.ipf.RequestMeta;
import cn.omisheep.authz.core.msg.RequestMessage;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import org.springframework.boot.logging.LogLevel;
import org.springframework.web.method.HandlerMethod;

import static cn.omisheep.authz.annotation.RateLimit.CheckType.IP;
import static cn.omisheep.authz.annotation.RateLimit.CheckType.USER_ID;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.1
 */
@Order(2)
public class RateLimitSlot implements Slot {

    private final Httpd httpd;

    public RateLimitSlot(Httpd httpd) {this.httpd = httpd;}

    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        String    ip         = httpMeta.getIp();
        long      now        = httpMeta.getNow().getTime();
        String    method     = httpMeta.getMethod();
        String    path       = httpMeta.getServletPath();
        String    api        = httpMeta.getApi();
        LimitMeta limitMeta  = httpd.getLimitMetadata(method, api);
        Object    userId     = null;
        String    deviceType = null;
        String    deviceId   = null;
        if (httpMeta.isHasToken()) {
            userId     = httpMeta.getToken().getUserId();
            deviceType = httpMeta.getToken().getDeviceType();
            deviceId   = httpMeta.getToken().getDeviceId();
        }

        if (limitMeta == null) {

            httpMeta.log("「普通访问」 \t api: [{}] ,  method: [{}] , ip : [{}] , userId : [{}] , deviceType: [{}] , deviceId: [{}] , path: [{}]  ", api, method, ip, userId, deviceType, deviceId, path);
            return;
        }
        RequestMessage requestMessage = new RequestMessage(method, api, ip, userId, now);
        Async.run(() -> RedisUtils.publish(RequestMessage.CHANNEL, requestMessage));

        RateLimit.CheckType checkType = limitMeta.getCheckType();

        Httpd.RequestPool ipRequestPool     = httpd.getIpRequestPools().get(method).get(api);
        Httpd.RequestPool userIdRequestPool = httpd.getUserIdRequestPools().get(method).get(api);

        if (checkType.equals(USER_ID) && userId == null) return;
        RequestMeta requestMeta = checkType.equals(IP) ? ipRequestPool.get(ip) : userIdRequestPool.get(userId.toString());
        if (requestMeta != null && requestMeta.isBan()) {
            if (!requestMeta.enableRelive(now)) {
                httpMeta.log(LogLevel.WARN, "「请求频繁、{}封锁(拒绝)」 \t api: [{}] , 距上次访问: [{}] , method: [{}] , ip : [{}] , userId : [{}] , deviceType: [{}] , deviceId: [{}] , path: [{}]  ", checkType, api, requestMeta.sinceLastTime(), method, ip, userId, deviceType, deviceId, path);
                error.error(ExceptionStatus.REQUEST_REPEAT);
                requestMeta.setLastRequestTime(now);
                return;
            } else {
                httpMeta.log("「解除{}封禁(解封)」 \t api: [{}] , 距上次访问: [{}] , method: [{}] , ip : [{}] , userId : [{}] , deviceType: [{}] , deviceId: [{}] , path: [{}]  ", checkType, api, requestMeta.sinceLastTime(), method, ip, userId, deviceType, deviceId, path);
                httpd.relive(requestMeta, limitMeta, method, api);
            }
        }
        if (requestMeta == null) {
            if (checkType.equals(IP)) {
                ipRequestPool.put(ip, new RequestMeta(now, ip, null));
            } else {
                userIdRequestPool.put(userId.toString(), new RequestMeta(now, null, userId));
            }
            httpMeta.log("「普通访问(首次)」 \t method: [{}] , api: [{}] , ip : [{}] , userId: [{}] , deviceType: [{}] , deviceId: [{}] , path: [{}]  ", method, api, ip, userId, deviceType, deviceId, path);
        } else {
            if (requestMeta.request(now, limitMeta.getMaxRequests(), limitMeta.getWindow(), limitMeta.getMinInterval())) {
                httpMeta.log("「普通访问(正常)」 \t 距上次访问: [{}]  api: [{}] ,  method: [{}] , ip : [{}] , userId : [{}] , deviceType: [{}] , deviceId: [{}] , path: [{}]  ", requestMeta.sinceLastTime(), api, method, ip, userId, deviceType, deviceId, path);
            } else {
                httpd.forbid(now, requestMeta, limitMeta, method, api);
                httpMeta.log(LogLevel.WARN, "「请求频繁、{}封锁(封禁)」 \t api: [{}] , 距上次访问: [{}] , method: [{}] , ip : [{}] , userId : [{}] , deviceType: [{}] , deviceId: [{}] , path: [{}]  ", checkType, api, requestMeta.sinceLastTime(), method, ip, userId, deviceType, deviceId, path);
                error.error(ExceptionStatus.REQUEST_REPEAT);
            }
        }

    }

}
