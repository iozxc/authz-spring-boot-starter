package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.web.utils.HttpUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.lang.Nullable;

import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class AUtils implements ApplicationContextAware {

    public static ApplicationContext ctx;

    public static <T> T getBean(Class<T> clz) {
        return ctx.getBean(clz);
    }

    public static <T> T getBean(String name, Class<T> clz) {
        return ctx.getBean(name, clz);
    }

    public static <T> Map<String, T> getBeansOfType(Class<T> clz) {
        return ctx.getBeansOfType(clz);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        ctx = applicationContext;
    }

    @Nullable
    public static HttpMeta getCurrentHttpMeta() {
        try {
            HttpMeta currentHttpMeta = (HttpMeta) HttpUtils.getCurrentRequest().getAttribute(Constants.HTTP_META);
            return currentHttpMeta;
        } catch (Exception e) {
            return null;
        }
    }

    @Nullable
    public static Token getCurrentToken() {
        try {
            return getCurrentHttpMeta().getToken();
        } catch (Exception e) {
            return null;
        }
    }

}
