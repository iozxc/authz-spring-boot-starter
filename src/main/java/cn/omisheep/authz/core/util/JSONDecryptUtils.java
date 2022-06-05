package cn.omisheep.authz.core.util;

import cn.omisheep.commons.util.RsaHelper;
import cn.omisheep.commons.util.StringUtils;
import com.alibaba.fastjson.JSONObject;

import java.util.Arrays;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.5
 */
public class JSONDecryptUtils {

    public static JSONObject decrypt(String name, JSONObject obj, String key) {
        if (!StringUtils.hasText(name)) return null;
        String[] trace = Arrays.stream(name.split("\\.")).distinct().toArray(String[]::new);
        return decrypt(trace, obj, key);
    }

    public static JSONObject decrypt(String[] trace, JSONObject obj, String key) {
        if (obj == null) return null;

        if (trace.length == 1) {
            obj.put(trace[0], RsaHelper.decrypt(obj.get(trace[0]).toString(), key));
            return obj;
        } else {
            return null;
        }
    }
}
