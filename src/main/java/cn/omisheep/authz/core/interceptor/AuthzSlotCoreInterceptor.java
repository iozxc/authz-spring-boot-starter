package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.slot.Order;
import cn.omisheep.authz.core.slot.Slot;
import cn.omisheep.authz.core.util.LogUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.LinkedList;

import static cn.omisheep.authz.core.Constants.HTTP_META;


/**
 * 核心拦截器
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuthzSlotCoreInterceptor implements HandlerInterceptor {

    private final AuthzExceptionHandler authzExceptionHandler;
    private final LinkedList<Slot> slots = new LinkedList<>();

    public AuthzSlotCoreInterceptor(AuthzExceptionHandler authzExceptionHandler, Collection<Slot> slots) {
        this.authzExceptionHandler = authzExceptionHandler;
        slots.stream().sorted((v1, v2) -> {
            Order orderV1 = AnnotationUtils.getAnnotation(v1.getClass(), Order.class);
            Order orderV2 = AnnotationUtils.getAnnotation(v2.getClass(), Order.class);
            return (orderV1 != null ? orderV1.order() : v1.order())
                    - (orderV2 != null ? orderV2.order() : v2.order());
        }).forEach(this.slots::offer);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HttpMeta httpMeta = (HttpMeta) request.getAttribute(HTTP_META);
        AuthzException httpException = httpMeta.getAuthzException();
        if (httpException != null) {
            authzExceptionHandler.handle(request, response, httpException);
            LogUtils.exportLogsFromRequest(request);
            return false;
        }
        if (!(handler instanceof HandlerMethod)) return false;
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        try {
            boolean next = true;
            for (Slot slot : slots) if (next || slot.must()) next = slot.chain(httpMeta, handlerMethod);
            AuthzException exception = httpMeta.getAuthzException();
            if (exception != null) {
                authzExceptionHandler.handle(request, response, exception);
                return false;
            } else return true;
        } catch (Exception e) {
            e.printStackTrace();
            authzExceptionHandler.handle(request, response, new AuthzException(e.getCause(), ExceptionStatus.UNKNOWN));
            return false;
        }
    }

}
