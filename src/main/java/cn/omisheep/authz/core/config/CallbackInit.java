package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.callback.CreateAuthorizationInfoCallback;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.authz.core.oauth.OpenAuthHelper;
import org.springframework.context.ApplicationContext;

import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.1
 */
public class CallbackInit {
    private static ApplicationContext app;

    public static void rateLimitInit() {
        Map<String, RateLimitCallback> c1 = app.getBeansOfType(RateLimitCallback.class);
        if (!c1.isEmpty()) {
            c1.entrySet().stream().findAny().ifPresent(
                    entry ->
                            Httpd.setRateLimitCallback(entry.getValue()));
        }

        Map<String, CreateAuthorizationInfoCallback> c2 = app.getBeansOfType(CreateAuthorizationInfoCallback.class);
        if (!c2.isEmpty()) {
            c2.entrySet().stream().findAny().ifPresent(
                    entry -> OpenAuthHelper.setCreateAuthorizationInfoCallback(entry.getValue()));
        }

    }

    public static void callbackInit(ApplicationContext app) {
        CallbackInit.app = app;
        rateLimitInit();
    }
}
