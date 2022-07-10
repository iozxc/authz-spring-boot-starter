package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface AuthzExceptionHandler {
    /**
     * @param request              request
     * @param response             response
     * @param httpMeta             httpMeta
     * @param firstExceptionStatus 可为空
     * @param errorObjects 自定义Slot中error捕获的错误对象
     * @throws Exception 抛出异常
     */
    boolean handle(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta, ExceptionStatus firstExceptionStatus, List<Object> errorObjects) throws Exception;
}
