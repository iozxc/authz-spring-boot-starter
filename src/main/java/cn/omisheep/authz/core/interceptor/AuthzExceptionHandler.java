package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzException;
import org.checkerframework.checker.nullness.qual.NonNull;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface AuthzExceptionHandler {
    /**
     * @param request   request
     * @param response  response
     * @param exception 不为空
     * @return 是否继续通过
     * @throws Exception 抛出异常
     */
    boolean handle(HttpServletRequest request, HttpServletResponse response, @NonNull AuthzException exception) throws Exception;
}
