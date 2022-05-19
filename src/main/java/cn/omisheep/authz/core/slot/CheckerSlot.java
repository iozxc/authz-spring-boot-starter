package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.util.ExceptionUtils;
import org.springframework.web.method.HandlerMethod;

import java.util.Map;

import static cn.omisheep.authz.core.Constants.OPTIONS;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(1)
public class CheckerSlot implements Slot {

    private final PermissionDict permissionDict;

    public CheckerSlot(PermissionDict permissionDict) {
        this.permissionDict = permissionDict;
    }

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) {
        if (httpMeta == null || httpMeta.isMethod(OPTIONS) || httpMeta.isIgnore()) return false;
        AuthzException exception = ExceptionUtils.get(httpMeta.getRequest());
        if (exception != null) return false;
        return requireProtect(httpMeta.getMethod(), httpMeta.getApi());
    }

    private boolean requireProtect(String method, String api) {
        Map<String, PermRolesMeta> map = permissionDict.getRolePermission().get(method);
        if (map == null) return false;
        return map.get(api) != null;
    }

}
