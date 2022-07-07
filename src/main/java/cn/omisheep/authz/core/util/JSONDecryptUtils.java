package cn.omisheep.authz.core.util;

import cn.omisheep.commons.util.RSAHelper;
import cn.omisheep.commons.util.StringUtils;
import com.alibaba.fastjson.JSONObject;

import java.util.Arrays;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.5
 * @version 1.0.9
 */
public class JSONDecryptUtils {

    public static void decrypt(String name, JSONObject obj, String key) {
        if (!StringUtils.hasText(name)) return;
        String[] trace = Arrays.stream(name.split("\\.")).distinct().toArray(String[]::new);
        decrypt(trace, obj, key);
    }

    public static void decrypt(String[] trace, JSONObject obj, String key) {
        if (obj == null) return;

        if (trace.length == 1) {
            if (obj.get(trace[0]) instanceof String)
                obj.put(trace[0], RSAHelper.decrypt(obj.getString(trace[0]), key));
        } else {
            if (obj.get(trace[0]) instanceof JSONObject)
                decrypt(Arrays.copyOfRange(trace, 1, trace.length), obj.getJSONObject(trace[0]), key);
        }
    }
}
