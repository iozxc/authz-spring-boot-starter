package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.commons.util.CollectionUtils;
import org.springframework.web.method.HandlerMethod;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static cn.omisheep.authz.core.util.LogUtils.logs;


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(300)
public class APIPermSlot implements Slot {

    private final PermLibrary permLibrary;

    public APIPermSlot(PermLibrary permLibrary) {
        this.permLibrary = permLibrary;
    }

    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        if (!httpMeta.isHasApiAuth()) return;
        PermRolesMeta permRolesMeta = PermissionDict.getRolePermission().get(httpMeta.getApi()).get(
                httpMeta.getMethod());
        if (permRolesMeta.non()) return;

        Set<String> roles = null;
        if (!CollectionUtils.isEmpty(permRolesMeta.getRequireRoles())
                || !CollectionUtils.isEmpty(permRolesMeta.getExcludeRoles())) {
            roles = httpMeta.getRoles();
            if (!CollectionUtils.containsSub(permRolesMeta.getRequireRoles(), roles)
                    || CollectionUtils.containsSub(permRolesMeta.getExcludeRoles(), roles)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                error.error(ExceptionStatus.PERM_EXCEPTION);
                return;
            }
        }

        if (!CollectionUtils.isEmpty(permRolesMeta.getRequirePermissions())
                || !CollectionUtils.isEmpty(permRolesMeta.getExcludePermissions())) {
            HashSet<String> perms = new HashSet<>(); // 用户所拥有的权限
            for (String role : Optional.ofNullable(httpMeta.getRoles()).orElse(new HashSet<>())) {
                Collection<String> permissionsByRole = permLibrary.getPermissionsByRole(role);
                if (permissionsByRole != null) perms.addAll(permissionsByRole);
                if (CollectionUtils.containsSub(permRolesMeta.getExcludePermissions(), permissionsByRole)) {
                    logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                    error.error(ExceptionStatus.PERM_EXCEPTION);
                    return;
                }
            }
            if (!CollectionUtils.containsSub(permRolesMeta.getRequirePermissions(), perms)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                error.error(ExceptionStatus.PERM_EXCEPTION);
                return;
            }
            httpMeta.setPermissions(perms);
        }

        logs("Success: API", httpMeta, permRolesMeta);
    }
}
