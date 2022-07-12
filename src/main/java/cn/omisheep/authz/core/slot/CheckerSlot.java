package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.util.ExceptionUtils;
import org.springframework.web.method.HandlerMethod;

import java.util.Map;
import java.util.Set;

import static cn.omisheep.authz.core.config.Constants.OPTIONS;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(10)
public class CheckerSlot implements Slot {

    private final PermissionDict permissionDict;

    public CheckerSlot(PermissionDict permissionDict) {
        this.permissionDict = permissionDict;
    }

    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        if (httpMeta == null || httpMeta.isMethod(OPTIONS) || httpMeta.isIgnore()) {
            error.error(null);
            return;
        }
        AuthzException exception = ExceptionUtils.get(httpMeta.getRequest());
        if (exception != null) {
            error.error(null);
            return;
        }
        httpMeta.setRequireProtect(requireProtect(httpMeta));
        httpMeta.setRequireLogin(requireLogin(httpMeta));
        if (httpMeta.isRequireProtect() || httpMeta.isRequireLogin()) {
            return;
        } else error.error(null);
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
