package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.web.utils.HttpUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public abstract class ExceptionUtils {
    private static final String AUTHZ_EXCEPTION = "AUTHZ_EXCEPTION";

    public static void error(ExceptionStatus exceptionStatus, Throwable e) {
        error(HttpUtils.getCurrentRequest(), new AuthzException(e, exceptionStatus));
    }

    public static void error(HttpServletRequest request, AuthzException authzException) {
        request.setAttribute(AUTHZ_EXCEPTION, authzException);
    }

    public static AuthzException get() {
        return get(HttpUtils.getCurrentRequest());
    }

    public static AuthzException get(HttpServletRequest request) {
        Object exception = request.getAttribute(AUTHZ_EXCEPTION);
        if (exception instanceof AuthzException) {
            return (AuthzException) exception;
        } else {
            return null;
        }
    }

    public static AuthzException pop(HttpServletRequest request) {
        AuthzException authzException = get(request);
        request.removeAttribute(AUTHZ_EXCEPTION);
        return authzException;
    }

}
