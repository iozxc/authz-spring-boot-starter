package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.commons.util.Async;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class SuccessSlot implements Slot {

    private final UserDevicesDict userDevicesDict;

    public SuccessSlot(UserDevicesDict userDevicesDict) {
        this.userDevicesDict = userDevicesDict;
    }

    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        Async.run(() -> userDevicesDict.request(httpMeta));
    }

}
