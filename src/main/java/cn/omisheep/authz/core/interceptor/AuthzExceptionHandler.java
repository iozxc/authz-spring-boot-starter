package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzException;

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
     * @throws Exception 抛出异常
     */
    boolean handle(HttpServletRequest request, HttpServletResponse response, AuthzException exception) throws Exception;
}
