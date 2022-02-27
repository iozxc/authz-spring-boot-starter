package cn.omisheep.authz.core.auth.rpd;

import com.sun.javafx.collections.ObservableMapWrapper;
import com.sun.javafx.collections.UnmodifiableObservableMap;

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
    private Map<String, Map<String, PermRolesMeta>> authzMetadata;

    private UnmodifiableObservableMap<String, Map<String, PermRolesMeta>> unmodifiableAuthzMetadata;

    public static String getPermSeparator() {
        return permSeparator;
    }

    public static void setPermSeparator(String permSeparator) {
        PermissionDict.permSeparator = permSeparator;
    }

    public Map<String, Map<String, PermRolesMeta>> getAuthzMetadata() {
        return unmodifiableAuthzMetadata;
    }

    public synchronized void init(Map<String, Map<String, PermRolesMeta>> authzMetadata) throws IllegalAccessException {
        if (this.authzMetadata != null) throw new IllegalAccessException("authzMetadata 已经初始化");
        this.authzMetadata = authzMetadata;
        unmodifiableAuthzMetadata = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(authzMetadata));
    }

    public synchronized PermRolesMeta modify(PermRolesMeta.Vo permRolesMetaVo) {
        try {
            switch (permRolesMetaVo.getOperate()) {
                case ADD:
                    return authzMetadata.get(permRolesMetaVo.getMethod()).put(permRolesMetaVo.getApi(), permRolesMetaVo.build());
                case MODIFY:
                    return authzMetadata.get(permRolesMetaVo.getMethod()).get(permRolesMetaVo.getApi()).merge(permRolesMetaVo.build());
                case DELETE:
                    return authzMetadata.get(permRolesMetaVo.getMethod()).remove(permRolesMetaVo.getApi());
                case GET:
                    return authzMetadata.get(permRolesMetaVo.getMethod()).get(permRolesMetaVo.getApi());
                default:
                    return null;
            }
        } catch (Exception e) {
            return null;
        } finally {
            unmodifiableAuthzMetadata = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(authzMetadata));
        }
    }

}
