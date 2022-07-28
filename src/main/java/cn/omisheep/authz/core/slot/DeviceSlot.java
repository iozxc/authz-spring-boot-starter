package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.*;
import static cn.omisheep.authz.core.auth.rpd.AuthzDefender.logs;

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
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        if (!httpMeta.isRequireLogin()) return;

        if (!httpMeta.isHasToken()) {
            logs("Require Login", httpMeta);
            error.error(ExceptionStatus.REQUIRE_LOGIN);
            return;
        }

        switch (userDevicesDict.userStatus(httpMeta.getToken())) {
            case REQUIRE_LOGIN:
                // 需要重新登录
                logs("Require Login", httpMeta);
                error.error(ExceptionStatus.REQUIRE_LOGIN);
                httpMeta.setTokenChecked(REQUIRE_LOGIN);
                return;
            case LOGIN_EXCEPTION:
                // 在别处登录
                logs("forbid : may have logged in elsewhere", httpMeta);
                error.error(ExceptionStatus.LOGIN_EXCEPTION);
                httpMeta.setTokenChecked(LOGIN_EXCEPTION);
                return;
        }
        httpMeta.setTokenChecked(SUCCESS);

    }

}
