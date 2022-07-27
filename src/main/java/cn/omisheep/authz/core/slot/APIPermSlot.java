package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.commons.util.CollectionUtils;
import org.springframework.web.method.HandlerMethod;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static cn.omisheep.authz.core.auth.rpd.AuthzDefender.logs;

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
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        if (!httpMeta.isRequireProtect()) return;
        PermRolesMeta permRolesMeta = PermissionDict.getRolePermission().get(httpMeta.getApi()).get(
                httpMeta.getMethod());
        if (permRolesMeta.non()) return;

        Token accessToken = httpMeta.getToken();

        Set<String> roles = null;
        boolean     e1    = CollectionUtils.isEmpty(permRolesMeta.getRequireRoles());
        boolean     e2    = CollectionUtils.isEmpty(permRolesMeta.getExcludeRoles());
        if (!e1 || !e2) {
            roles = permLibrary.getRolesByUserId(accessToken.getUserId());
            httpMeta.setRoles(roles);
            if (!e1 && !CollectionUtils.containsSub(permRolesMeta.getRequireRoles(),
                                                    roles) || !e2 && CollectionUtils.containsSub(
                    permRolesMeta.getExcludeRoles(), roles)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                error.error(ExceptionStatus.PERM_EXCEPTION);
                return;
            }
        }

        boolean e3 = CollectionUtils.isEmpty(permRolesMeta.getRequirePermissions());
        boolean e4 = CollectionUtils.isEmpty(permRolesMeta.getExcludePermissions());
        if (!e3 || !e4) {
            if (e1 && e2) {
                roles = permLibrary.getRolesByUserId(accessToken.getUserId());
                httpMeta.setRoles(roles);
            }
            HashSet<String> perms = new HashSet<>(); // 用户所拥有的权限
            for (String role : Optional.ofNullable(roles).orElse(new HashSet<>())) {
                Set<String> permissionsByRole = permLibrary.getPermissionsByRole(role);
                perms.addAll(permissionsByRole);
                if (!e4 && CollectionUtils.containsSub(permRolesMeta.getExcludePermissions(), permissionsByRole)) {
                    logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                    error.error(ExceptionStatus.PERM_EXCEPTION);
                    return;
                }
            }
            if (!e3 && !CollectionUtils.containsSub(permRolesMeta.getRequirePermissions(), perms)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                error.error(ExceptionStatus.PERM_EXCEPTION);
                return;
            }
            httpMeta.setPermissions(perms);
        }

        logs("Success: API", httpMeta, permRolesMeta);
    }
}
