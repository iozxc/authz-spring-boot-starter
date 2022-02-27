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
