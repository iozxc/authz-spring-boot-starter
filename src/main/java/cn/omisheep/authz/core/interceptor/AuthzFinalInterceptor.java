package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.util.ExceptionUtils;
import cn.omisheep.authz.core.util.LogUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 异常错误拦截器，用户可继承
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class AuthzFinalInterceptor implements HandlerInterceptor {
    private final AuthzExceptionHandler authzExceptionHandler;

    public AuthzFinalInterceptor(AuthzExceptionHandler authzExceptionHandler) {
        this.authzExceptionHandler = authzExceptionHandler;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        LogUtils.exportLogsFromRequest(request);
        AuthzException exception = ExceptionUtils.clear(request);
        return exception == null || authzExceptionHandler.handle(request, response, exception);
    }

}
