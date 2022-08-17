package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.LogLevel;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.HttpUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class DefaultAuthzExceptionHandler implements AuthzExceptionHandler {

    private final AuthzProperties.ResponseConfig config;

    public DefaultAuthzExceptionHandler(AuthzProperties.ResponseConfig config) {this.config = config;}

    @Override
    public boolean handle(HttpServletRequest request,
                          HttpServletResponse response,
                          HttpMeta httpMeta,
                          ExceptionStatus exceptionStatus,
                          List<Object> errorObjects) throws Exception {
        if (exceptionStatus.equals(ExceptionStatus.MISMATCHED_URL)) {
            httpMeta.log(LogLevel.DEBUG,
                         "「普通访问(uri不存在)」 \tmethod: [{}] , ip : [{}] , path: [{}]   ",
                         httpMeta.getMethod(),
                         httpMeta.getIp(), httpMeta.getApi());
            return true;
        }

        if (config.isAlwaysOk()) {
            HttpUtils.returnResponse(200, exceptionStatus.data());
        } else {
            HttpUtils.returnResponse(exceptionStatus.getHttpStatus(), exceptionStatus.data());
        }

        return false;
    }

}
