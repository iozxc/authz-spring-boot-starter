package cn.omisheep.authz.core.util;

import cn.omisheep.commons.util.StringUtils;
import cn.omisheep.commons.util.web.JSONUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class FormatUtils {

    private FormatUtils() {
        throw new UnsupportedOperationException();
    }

    private static final Pattern JSON_RSA_PATTERN = Pattern.compile("\\{.*\".*\".*:.*\"(.*)\".*}");

    public static String parseRSAJson(String json) {
        Matcher matcher = JSON_RSA_PATTERN.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    public static String beautifulJson(Object o) {
        return JSONUtils.toPrettyJSONString(o);
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
