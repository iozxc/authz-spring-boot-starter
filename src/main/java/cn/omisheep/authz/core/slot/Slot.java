package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

/**
 * {@link Error}
 * <p>
 * <p>
 * (1) CookieAndRequestSlot(1)  <br>
 * (2) RateLimitSlot(2)         <br>
 * (3) BlacklistSlot(5)         <br>
 * (4) CheckerSlot(10)          <br>
 * (5) IPRangeSlot(30)          <br>
 * (6) DeviceSlot(100)          <br>
 * (7) APIPermSlot(300)         <br>
 * (8) ParameterPermSlot(400)   <br>
 * (9) LogSlot(Int:max)         <br>
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface Slot {

    default int order() {
        return Integer.MAX_VALUE;
    }

    default boolean must() {
        return false;
    }

    void chain(HttpMeta httpMeta, HandlerMethod handler, Error error);
}
