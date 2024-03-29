package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.UserStatus.*;
import static cn.omisheep.authz.core.util.LogUtils.logs;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(100)
public class DeviceSlot implements Slot {

    private final UserDevicesDict userDevicesDict;

    public DeviceSlot(UserDevicesDict userDevicesDict) {
        this.userDevicesDict = userDevicesDict;
    }

    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        if (!httpMeta.isRequireLogin()) return;

        if (httpMeta.getUserStatus() != null) {
            if (httpMeta.getUserStatus().equals(ACCESS_TOKEN_OVERDUE)) {
                logs("Forbid : expired token exception", httpMeta);
                error.error(ExceptionStatus.ACCESS_TOKEN_OVERDUE);
            } else if (httpMeta.getUserStatus().equals(REQUIRE_LOGIN)) {
                logs("Require Login", httpMeta);
                error.error(ExceptionStatus.REQUIRE_LOGIN);
            }
            return;
        }

        if (!httpMeta.hasToken()) {
            logs("Require Login", httpMeta);
            error.error(ExceptionStatus.REQUIRE_LOGIN);
            return;
        }

        switch (userDevicesDict.userStatus(httpMeta.getToken())) {
            case REQUIRE_LOGIN:
                // 需要重新登录
                logs("Require Login", httpMeta);
                error.error(ExceptionStatus.REQUIRE_LOGIN);
                httpMeta.setUserStatus(REQUIRE_LOGIN);
                return;
            case LOGIN_EXCEPTION:
                // 在别处登录
                logs("forbid : may have logged in elsewhere", httpMeta);
                error.error(ExceptionStatus.LOGIN_EXCEPTION);
                httpMeta.setUserStatus(LOGIN_EXCEPTION);
                return;
        }
        httpMeta.setUserStatus(SUCCESS);

    }

}
