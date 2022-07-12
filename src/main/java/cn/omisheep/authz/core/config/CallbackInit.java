package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import org.springframework.context.ApplicationContext;

import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.1
 */
public class CallbackInit {
    private static ApplicationContext app;

    public static void rateLimitInit() {
        Map<String, RateLimitCallback> beansOfType = app.getBeansOfType(RateLimitCallback.class);
        if (beansOfType.isEmpty()) return;
        beansOfType.entrySet().stream().findAny().ifPresent(
                stringRateLimitCallbackEntry ->
                        Httpd.setRateLimitCallback(stringRateLimitCallbackEntry.getValue()));
    }

    public static void callbackInit(ApplicationContext app) {
        CallbackInit.app = app;
        rateLimitInit();
    }
}
