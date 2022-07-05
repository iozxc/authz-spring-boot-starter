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
 * (1) CookieAndRequestSlot(5)  <br>
 * (2) CheckerSlot(10)          <br>
 * (3) IPRangeSlot(30)          <br>
 * (4) DeviceSlot(100)          <br>
 * (5) APIPermSlot(300)         <br>
 * (6) ParameterPermSlot(400)   <br>
 * (7) LogSlot(Int:max)         <br>
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

    boolean chain(HttpMeta httpMeta, HandlerMethod handler) throws AuthzException, Exception;
}
