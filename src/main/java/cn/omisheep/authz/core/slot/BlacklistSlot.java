package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.LogLevel;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.0
 */
@Order(15)
@SuppressWarnings("all")
public class BlacklistSlot implements Slot {
    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        boolean check = Blacklist.check(httpMeta.getIp(), httpMeta.getToken());
        if (check) return;
        String ip         = httpMeta.getIp();
        String method     = httpMeta.getMethod();
        String path       = httpMeta.getServletPath();
        String api        = httpMeta.getApi();
        Object userId     = null;
        String deviceType = null;
        String deviceId   = null;
        String clientId   = null;
        if (httpMeta.hasToken()) {
            userId     = httpMeta.getToken().getUserId();
            deviceType = httpMeta.getToken().getDeviceType();
            deviceId   = httpMeta.getToken().getDeviceId();
            clientId   = httpMeta.getToken().getClientId();
        }
        httpMeta.log(LogLevel.WARN,
                     "「请求拒绝」\t method: [{}], api: [{}] , path: [{}] , ip : [{}] , clientId : [{}] , userId : [{}] , deviceType: [{}] , deviceId: [{}] ",
                     method, api, path, ip, clientId, userId, deviceType, deviceId);
        error.error(ExceptionStatus.REQUEST_EXCEPTION);
        return;
    }
}
