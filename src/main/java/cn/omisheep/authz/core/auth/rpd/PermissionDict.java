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
        boolean change = false;
        try {
            Map<String, PermRolesMeta> target = authzMetadata.get(permRolesMetaVo.getMethod());
            PermRolesMeta meta = target.get(permRolesMetaVo.getApi());
            switch (permRolesMetaVo.getOperate()) {
                case ADD:
                case OVERRIDE:
                    change = true;
                    if (meta != null) return meta.overrideApi(permRolesMetaVo.build());
                    else return target.put(permRolesMetaVo.getApi(), permRolesMetaVo.build());
                case MODIFY:
                case UPDATE:
                    change = true;
                    return meta.merge(permRolesMetaVo.build());
                case DELETE:
                case DEL:
                    if (meta != null) return meta.removeApi();
                    else return null;
                case GET:
                case READ:
                    return meta;
                default:
                    return null;
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (change) {
                PermRolesMeta meta = authzMetadata.get(permRolesMetaVo.getMethod()).get(permRolesMetaVo.getApi());
                if (meta == null || meta.nonAll()) {
                    authzMetadata.get(permRolesMetaVo.getMethod()).remove(permRolesMetaVo.getApi());
                }
                Map<String, PermRolesMeta> metaMap = authzMetadata.get(permRolesMetaVo.getMethod());
                if (metaMap.size() == 0) authzMetadata.remove(permRolesMetaVo.getMethod());
            }
            unmodifiableAuthzMetadata = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(authzMetadata));
        }
    }

}
