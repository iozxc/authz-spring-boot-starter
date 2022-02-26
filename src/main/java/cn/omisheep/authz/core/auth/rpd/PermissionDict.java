package cn.omisheep.authz.core.auth.rpd;

import java.util.HashMap;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class PermissionDict {

    private static String permSeparator = ",";

    /**
     * 权限
     */
    private final Map<String, Map<String, PermRolesMeta>> authzMetadata = new HashMap<>();

    public static String getPermSeparator() {
        return permSeparator;
    }

    public static void setPermSeparator(String permSeparator) {
        PermissionDict.permSeparator = permSeparator;
    }

    public Map<String, Map<String, PermRolesMeta>> getAuthzMetadata() {
        return authzMetadata;
    }

}
