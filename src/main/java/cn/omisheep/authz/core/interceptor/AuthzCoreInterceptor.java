package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.rpd.AuthzDefender;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.ExceptionUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static cn.omisheep.authz.core.Constants.HTTP_META;
import static cn.omisheep.authz.core.Constants.OPTIONS;


/**
 * 核心拦截器
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuthzCoreInterceptor implements HandlerInterceptor {

    private final AuthzDefender auDefender;

    public AuthzCoreInterceptor(AuthzDefender auDefender) {
        this.auDefender = auDefender;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        AuthzException authzException = ExceptionUtils.get(request);
        if (authzException != null) return true;
        if (!(handler instanceof HandlerMethod)) {
            return false;
        }
        HandlerMethod hm = (HandlerMethod) handler;

        // 状态获取初始化
        HttpMeta httpMeta = (HttpMeta) request.getAttribute(HTTP_META);

        // 如果是OPTIONS请求，直接放行
        if (httpMeta.isMethod(OPTIONS)) return true;

        // 不需要保护直接放行
        if (!auDefender.requireProtect(httpMeta.getMethod(), httpMeta.getApi())) {
            return true;
        }

        try {
            ExceptionStatus error = auDefender.verify(httpMeta);
            if (error != null) ExceptionUtils.error(error);
        } catch (Exception e) {
            e.printStackTrace();
            ExceptionUtils.error(ExceptionStatus.UNKNOWN, e.getCause());
        }
        return true;
    }

}
