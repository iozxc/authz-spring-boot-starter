package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.slot.Order;
import cn.omisheep.authz.core.slot.Slot;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.util.LogUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;

import static cn.omisheep.authz.core.Constants.HTTP_META;


/**
 * Slot执行器
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuthzSlotCoreInterceptor implements HandlerInterceptor {

    private final AuthzExceptionHandler authzExceptionHandler;
    private final LinkedList<Slot>      slots = new LinkedList<>();

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
        HttpMeta       httpMeta      = (HttpMeta) request.getAttribute(HTTP_META);
        AuthzException httpException = httpMeta.getAuthzException();
        if (httpException != null) {
            LogUtils.exportLogsFromRequest(request);
            return authzExceptionHandler.handle(request, response, httpMeta, httpException.getExceptionStatus());
        }
        if (!(handler instanceof HandlerMethod)) return false;
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        try {
            boolean next = true;
            Date    date = new Date();
            for (Slot slot : slots) if (next || slot.must()) {
                next = slot.chain(httpMeta, handlerMethod);
                System.out.println(slot.getClass());
                System.out.println(new Date().getTime()- date.getTime());
            }
            System.out.println(new Date().getTime()- date.getTime());
            AuthzException exception = httpMeta.getAuthzException();
            if (exception != null) {
                if (exception.getExceptionStatus().isClearToken()) TokenHelper.clearCookie(response);
                return authzExceptionHandler.handle(request, response, httpMeta, exception.getExceptionStatus());
            } else return true;
        } catch (Exception e) {
            e.printStackTrace();
            LogUtils.logError(e.getMessage(), e.getCause());
            return authzExceptionHandler.handle(request, response, httpMeta, ExceptionStatus.UNKNOWN);
        }
    }

}
