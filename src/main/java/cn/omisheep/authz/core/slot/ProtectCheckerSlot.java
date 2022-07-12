package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import org.springframework.web.method.HandlerMethod;

import java.util.Map;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(10)
public class ProtectCheckerSlot implements Slot {

    private final PermissionDict permissionDict;

    public ProtectCheckerSlot(PermissionDict permissionDict) {
        this.permissionDict = permissionDict;
    }

    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        httpMeta.setRequireProtect(requireProtect(httpMeta));
        httpMeta.setRequireLogin(requireLogin(httpMeta));
    }

    private boolean requireProtect(HttpMeta httpMeta) {
        Map<String, PermRolesMeta> map = permissionDict.getRolePermission().get(httpMeta.getMethod());
        if (map == null) return false;
        return map.get(httpMeta.getApi()) != null;
    }

    private boolean requireLogin(HttpMeta httpMeta) {
        Set<String> list = permissionDict.getCertificatedMetadata().get(httpMeta.getMethod());
        if (list == null) return httpMeta.isRequireProtect();
        return list.contains(httpMeta.getApi()) || httpMeta.isRequireProtect();
    }

}
