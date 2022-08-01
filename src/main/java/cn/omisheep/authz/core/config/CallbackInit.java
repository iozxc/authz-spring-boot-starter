package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.callback.AuthorizationCallback;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.authz.core.helper.OpenAuthHelper;
import org.springframework.context.ApplicationContext;

import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.1
 */
public class CallbackInit {
    private static ApplicationContext app;

    public static void rateLimitInit() {
        Map<String, RateLimitCallback> c = app.getBeansOfType(RateLimitCallback.class);
        if (!c.isEmpty()) {
            c.entrySet().stream().findAny().ifPresent(
                    entry ->
                            Httpd.setRateLimitCallback(entry.getValue()));
        }
    }

    public static void authorizationInit() {
        Map<String, AuthorizationCallback> c = app.getBeansOfType(AuthorizationCallback.class);
        if (!c.isEmpty()) {
            c.entrySet().stream().findAny().ifPresent(
                    entry -> OpenAuthHelper.setAuthorizationCallback(entry.getValue()));
        }
    }

    public static void callbackInit(ApplicationContext app) {
        CallbackInit.app = app;
        rateLimitInit();
        authorizationInit();
    }
}
