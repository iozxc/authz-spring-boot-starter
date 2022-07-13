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
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicBoolean;

import static cn.omisheep.authz.core.config.Constants.HTTP_META;


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
        HttpMeta httpMeta = (HttpMeta) request.getAttribute(HTTP_META);
        if (httpMeta == null) return true;
        LinkedList<ExceptionStatus> list = httpMeta.getExceptionStatusList();
        if (!list.isEmpty()) {
            httpMeta.exportLog();
            return authzExceptionHandler.handle(request, response, httpMeta, list.getFirst(), httpMeta.getExceptionObjectList());
        }
        httpMeta.clearError();
        if (!(handler instanceof HandlerMethod)) return false;
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        try {
            AtomicBoolean               next                = new AtomicBoolean(true);
            LinkedList<ExceptionStatus> exceptionStatusList = httpMeta.getExceptionStatusList();
            LinkedList<Object>          exceptionObjectList = httpMeta.getExceptionObjectList();
            for (Slot slot : slots) {
                if (next.get() || slot.must()) slot.chain(httpMeta, handlerMethod, (error) -> {
                    next.set(false);
                    if (error == null) return;
                    if (error instanceof ExceptionStatus) {
                        exceptionStatusList.offer((ExceptionStatus) error);
                    } else if (error instanceof AuthzException) {
                        exceptionStatusList.offer(((AuthzException) error).getExceptionStatus());
                    } else {
                        exceptionObjectList.offer(error);
                    }
                });
            }
            if (!exceptionStatusList.isEmpty() || !exceptionObjectList.isEmpty()) {
                ExceptionStatus status = exceptionStatusList.getFirst();
                if (status != null && status.isClearToken()) {
                    TokenHelper.clearCookie(response);
                }
                return authzExceptionHandler.handle(request, response, httpMeta, status, exceptionObjectList);
            } else return true;
        } catch (Exception e) {
            LogUtils.error(e);
            return authzExceptionHandler.handle(request, response, httpMeta, ExceptionStatus.UNKNOWN, httpMeta.getExceptionObjectList());
        }
    }

}
