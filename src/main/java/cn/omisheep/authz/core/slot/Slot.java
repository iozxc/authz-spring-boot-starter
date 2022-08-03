package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

/**
 * {@link Error}
 * <p>
 * <p>
 * (0)        FilterSlot               <br>
 * (1)        CookieAndRequestSlot     <br>
 * (10)       RateLimitSlot            <br>
 * (15)       BlacklistSlot            <br>
 * (30)       IPRangeSlot              <br>
 * (50)       OAuthSlot                <br>
 * (100)      DeviceSlot               <br>
 * (300)      APIPermSlot              <br>
 * (400)      ParameterPermSlot        <br>
 * (Int:max)  LogSlot                  <br>
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
