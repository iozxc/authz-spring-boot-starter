package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.web.entity.Result;
import cn.omisheep.web.utils.HttpUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class DefaultAuthzExceptionHandler implements AuthzExceptionHandler {
    @Override
    public boolean handle(HttpServletRequest request, HttpServletResponse response,
                          HttpMeta httpMeta, ExceptionStatus firstExceptionStatus, List<Object> errorObjects) throws Exception {
        if (firstExceptionStatus.equals(ExceptionStatus.MISMATCHED_URL)) return true;

        HttpUtils.returnResponse(firstExceptionStatus.getHttpStatus(),
                Result.of(firstExceptionStatus.getCode(), firstExceptionStatus.getMessage()));

        return false;
    }
}
