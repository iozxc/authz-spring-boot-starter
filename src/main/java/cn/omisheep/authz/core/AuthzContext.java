package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.web.utils.HttpUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.NonNull;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class AuthzContext {

    public static final ThreadLocal<HttpMeta> httpMeta = ThreadLocal.withInitial(() -> null);

    private AuthzContext() {
        throw new UnsupportedOperationException();
    }

    private static ApplicationContext ctx;

    public static <T> T getBean(Class<T> clz) {
        return ctx.getBean(clz);
    }

    public static <T> T getBean(String name,
                                Class<T> clz) {
        return ctx.getBean(name, clz);
    }

    public static <T> Map<String, T> getBeansOfType(Class<T> clz) {
        return ctx.getBeansOfType(clz);
    }

    public static void init(ApplicationContext applicationContext) {
        ctx = applicationContext;
    }

    public static ApplicationContext getCtx() {
        return ctx;
    }

    @NonNull
    public static HttpMeta getCurrentHttpMeta() throws ThreadWebEnvironmentException {
        try {
            if (httpMeta.get() != null) return httpMeta.get();
            HttpMeta currentHttpMeta = (HttpMeta) HttpUtils.getCurrentRequest().getAttribute(Constants.HTTP_META);
            if (currentHttpMeta == null) throw new ThreadWebEnvironmentException();
            return currentHttpMeta;
        } catch (Exception e) {
            throw new ThreadWebEnvironmentException();
        }
    }

    @NonNull
    public static AccessToken getCurrentToken() throws NotLoginException {
        try {
            AccessToken accessToken = getCurrentHttpMeta().getToken();
            if (accessToken == null) throw new NotLoginException();
            return accessToken;
        } catch (Exception e) {
            throw new NotLoginException();
        }
    }

    public static Object createUserId(String userId) {
        try {
            if (AuthzAppVersion.USER_ID_TYPE.equals(String.class)) return userId;
            return AuthzAppVersion.USER_ID_CONSTRUCTOR.newInstance(userId);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            return userId;
        }
    }

}
