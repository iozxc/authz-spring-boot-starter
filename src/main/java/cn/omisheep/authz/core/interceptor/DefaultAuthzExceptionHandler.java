package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.web.entity.Result;
import cn.omisheep.web.utils.HttpUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class DefaultAuthzExceptionHandler implements AuthzExceptionHandler {
    @Override
    public boolean handle(HttpServletRequest request, HttpServletResponse response,
                          HttpMeta httpMeta, ExceptionStatus exceptionStatus) throws Exception {
        if (exceptionStatus.equals(ExceptionStatus.MISMATCHED_URL)) return true;

        HttpUtils.returnResponse(exceptionStatus.getHttpStatus(),
                Result.of(exceptionStatus.getCode(), exceptionStatus.getMessage()));

        return false;
    }
}
