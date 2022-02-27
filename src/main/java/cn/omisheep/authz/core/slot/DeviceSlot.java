package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.tk.Token;
import org.springframework.web.method.HandlerMethod;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.*;
import static cn.omisheep.authz.core.auth.rpd.AuthzDefender.logs;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(10)
public class DeviceSlot implements Slot {

    private final PermissionDict permissionDict;
    private final UserDevicesDict userDevicesDict;

    public DeviceSlot(PermissionDict permissionDict, UserDevicesDict userDevicesDict) {
        this.permissionDict = permissionDict;
        this.userDevicesDict = userDevicesDict;
    }

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) {
        PermRolesMeta permRolesMeta = permissionDict.getAuthzMetadata().get(httpMeta.getMethod()).get(httpMeta.getApi());
        if (permRolesMeta.non()) return true;

        if (!httpMeta.isHasTokenCookie()) {
            logs("Require Login", httpMeta, permRolesMeta);
            httpMeta.error(ExceptionStatus.REQUIRE_LOGIN);
            return false;
        }

        if (httpMeta.getTokenException() != null) {
            switch (httpMeta.getTokenException()) {
                case ExpiredJwtException:
                    logs("Forbid : expired token exception", httpMeta, permRolesMeta);
                    httpMeta.error(ExceptionStatus.ACCESS_TOKEN_OVERDUE);
                    return false;
                case MalformedJwtException:
                    logs("Forbid : malformed token exception", httpMeta, permRolesMeta);
                    httpMeta.error(ExceptionStatus.TOKEN_EXCEPTION);
                    return false;
                case SignatureException:
                    logs("Forbid : signature exception", httpMeta, permRolesMeta);
                    httpMeta.error(ExceptionStatus.TOKEN_EXCEPTION);
                    return false;
            }
        }

        Token accessToken = httpMeta.getToken();

        switch (userDevicesDict.userStatus(accessToken.getUserId(), accessToken.getDeviceType(), accessToken.getDeviceId(), accessToken.getTokenId())) {
            case ACCESS_TOKEN_OVERDUE:
                // accessToken过期
                logs("Forbid : expired token exception", httpMeta, permRolesMeta);
                httpMeta.error(ExceptionStatus.ACCESS_TOKEN_OVERDUE);
                return false;
            case REQUIRE_LOGIN:
                // 需要重新登录
                logs("Require Login", httpMeta, permRolesMeta);
                httpMeta.error(ExceptionStatus.REQUIRE_LOGIN);
                return false;
            case LOGIN_EXCEPTION:
                // 在别处登录
                logs("forbid : may have logged in elsewhere", httpMeta, permRolesMeta);
                httpMeta.error(ExceptionStatus.LOGIN_EXCEPTION);
                return false;
        }

        return true;
    }
}
