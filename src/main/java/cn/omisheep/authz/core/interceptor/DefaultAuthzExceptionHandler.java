package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzProperties;
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

    private final AuthzProperties.ResponseConfig config;

    public DefaultAuthzExceptionHandler(AuthzProperties.ResponseConfig config) {this.config = config;}

    @Override
    public boolean handle(HttpServletRequest request,
                          HttpServletResponse response,
                          HttpMeta httpMeta,
                          ExceptionStatus firstExceptionStatus,
                          List<Object> errorObjects) throws Exception {
        if (firstExceptionStatus.equals(ExceptionStatus.MISMATCHED_URL)) {
            httpMeta.log("「普通访问(uri不存在)」 \tmethod: [{}] , ip : [{}] , path: [{}]   ", httpMeta.getMethod(),
                         httpMeta.getIp(), httpMeta.getApi());
            return true;
        }

        if (config.isAlwaysOk()) {
            HttpUtils.returnResponse(200,
                                     Result.of(firstExceptionStatus.getCode(), firstExceptionStatus.getMessage()));
        } else {
            HttpUtils.returnResponse(firstExceptionStatus.getHttpStatus(),
                                     Result.of(firstExceptionStatus.getCode(), firstExceptionStatus.getMessage()));
        }

        return false;
    }
}
