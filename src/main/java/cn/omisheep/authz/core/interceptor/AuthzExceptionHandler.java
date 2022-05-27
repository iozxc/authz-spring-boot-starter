package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface AuthzExceptionHandler {
    /**
     * @param request         request
     * @param response        response
     * @param httpMeta        httpMeta
     * @param exceptionStatus 不为空
     * @throws Exception 抛出异常
     */
    boolean handle(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta, ExceptionStatus exceptionStatus) throws Exception;
}
