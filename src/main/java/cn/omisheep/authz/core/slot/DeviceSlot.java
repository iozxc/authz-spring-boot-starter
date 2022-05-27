package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.tk.Token;
import org.springframework.web.method.HandlerMethod;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.*;
import static cn.omisheep.authz.core.auth.rpd.AuthzDefender.logs;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(10)
public class DeviceSlot implements Slot {

    private final PermissionDict  permissionDict;
    private final UserDevicesDict userDevicesDict;

    public DeviceSlot(PermissionDict permissionDict, UserDevicesDict userDevicesDict) {
        this.permissionDict  = permissionDict;
        this.userDevicesDict = userDevicesDict;
    }

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) {
        if (!httpMeta.isRequireLogin()) return true;

        if (!httpMeta.isHasToken()) {
            logs("Require Login", httpMeta);
            httpMeta.error(ExceptionStatus.REQUIRE_LOGIN);
            return false;
        }

        Token accessToken = httpMeta.getToken();

        switch (userDevicesDict.userStatus(accessToken.getUserId(), accessToken.getDeviceType(), accessToken.getDeviceId(), accessToken.getTokenId())) {
            case ACCESS_TOKEN_OVERDUE:
                // accessToken过期
                logs("Forbid : expired token exception", httpMeta);
                httpMeta.error(ExceptionStatus.ACCESS_TOKEN_OVERDUE);
                return false;
            case REQUIRE_LOGIN:
                // 需要重新登录
                logs("Require Login", httpMeta);
                httpMeta.error(ExceptionStatus.REQUIRE_LOGIN);
                return false;
            case LOGIN_EXCEPTION:
                // 在别处登录
                logs("forbid : may have logged in elsewhere", httpMeta);
                httpMeta.error(ExceptionStatus.LOGIN_EXCEPTION);
                return false;
        }

        return true;
    }
}
