package cn.omisheep.authz.core.util;

import cn.omisheep.commons.util.StringUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static cn.omisheep.authz.core.config.AuInit.log;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public abstract class Utils {

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

    public static String format(String format,
                                Object... vals) {
        return StringUtils.format(format, vals);
    }

    public static boolean isIgnoreSuffix(String uri,
                                         String... suffix) {
        for (String s : suffix) {
            if (uri.endsWith(s)) return true;
        }
        return false;
    }

}
