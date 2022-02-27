package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.commons.util.HttpUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class AUtils implements ApplicationContextAware {

    private static ApplicationContext ctx;

    private static final Pattern JSON_RSA_PATTERN = Pattern.compile("\\{.*\".*\".*:.*\"(.*)\".*}");

    public static String parse_RSA_JSON(String json) {
        Matcher matcher = JSON_RSA_PATTERN.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    public static String beautifulJson(Object o) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(o);
        } catch (JsonProcessingException e) {
            log.error("JsonProcessingException => {}", e.getMessage());
            return "";
        }
    }

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

    public static HttpMeta getCurrentHttpMeta() {
        HttpMeta currentHttpMeta = (HttpMeta) HttpUtils.getCurrentRequest().getAttribute(Constants.HTTP_META);
        return currentHttpMeta;
    }


}
