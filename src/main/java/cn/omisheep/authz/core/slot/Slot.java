package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

/**
 * {@link HttpMeta#error(AuthzException)}
 * <p>
 * {@link HttpMeta#error(ExceptionStatus)}
 * <p>
 * {@link HttpMeta#error(ExceptionStatus, Throwable)}
 * <p>
 * <p>
 * (1) CookieAndRequestSlot(0)
 * (2) CheckerSlot(1)
 * (3) IPRangeSlot(3)
 * (4) DeviceSlot(10)
 * (5) APIPermSlot(30)
 * (6) ParameterPermSlot(40)
 * (7) LogSlot(Int:max)
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface Slot {

    default int order() {
        return Integer.MAX_VALUE;
    }

    default boolean must() {
        return false;
    }

    boolean chain(HttpMeta httpMeta, HandlerMethod handler) throws Exception;
}
