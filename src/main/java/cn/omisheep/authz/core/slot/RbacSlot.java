package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import org.springframework.web.method.HandlerMethod;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static cn.omisheep.authz.core.auth.rpd.AuthzDefender.logs;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
@Order(30)
public class RbacSlot implements Slot {

    private final PermissionDict permissionDict;
    private final PermLibrary permLibrary;

    public RbacSlot(PermissionDict permissionDict, PermLibrary permLibrary) {
        this.permissionDict = permissionDict;
        this.permLibrary = permLibrary;
    }

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) {
        PermRolesMeta permRolesMeta = permissionDict.getAuthzMetadata().get(httpMeta.getMethod()).get(httpMeta.getApi());
        if (permRolesMeta.non()) return true;

        Token accessToken = httpMeta.getToken();

        Set<String> roles = null;
        boolean e1 = CollectionUtils.isEmpty(permRolesMeta.getRequireRoles());
        boolean e2 = CollectionUtils.isEmpty(permRolesMeta.getExcludeRoles());
        if (!e1 || !e2) {
            long nowTime = TimeUtils.nowTime();
            roles = permLibrary.getRolesByUserId(accessToken.getUserId());
            LogUtils.logDebug("permLibrary.getRolesByUserId({})  {}", accessToken.getUserId(), TimeUtils.diff(nowTime));
            if (!e1 && !CollectionUtils.containsSub(permRolesMeta.getRequireRoles(), roles) || !e2 && CollectionUtils.containsSub(permRolesMeta.getExcludeRoles(), roles)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                httpMeta.error(ExceptionStatus.PERM_EXCEPTION);
                return false;
            }
        }

        boolean e3 = CollectionUtils.isEmpty(permRolesMeta.getRequirePermissions());
        boolean e4 = CollectionUtils.isEmpty(permRolesMeta.getExcludePermissions());
        if (!e3 || !e4) {
            if (e1 && e2) {
                long nowTime = TimeUtils.nowTime();
                roles = permLibrary.getRolesByUserId(accessToken.getUserId());
                LogUtils.logDebug("e1 && e2 permLibrary.getRolesByUserId({})  {}", accessToken.getUserId(), TimeUtils.diff(nowTime));
            }
            HashSet<String> perms = new HashSet<>(); // 用户所拥有的权限
            for (String role : Optional.of(roles).orElse(new HashSet<>())) {
                long nowTime = TimeUtils.nowTime();
                Set<String> permissionsByRole = permLibrary.getPermissionsByRole(role);
                LogUtils.logDebug("permLibrary.getPermissionsByRole({}) {}", role, TimeUtils.diff(nowTime));
                perms.addAll(permissionsByRole);
                if (!e4 && CollectionUtils.containsSub(permRolesMeta.getExcludePermissions(), permissionsByRole)) {
                    logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                    httpMeta.error(ExceptionStatus.PERM_EXCEPTION);
                    return false;

                }
            }
            if (!e3 && !CollectionUtils.containsSub(permRolesMeta.getRequirePermissions(), perms)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                httpMeta.error(ExceptionStatus.PERM_EXCEPTION);
                return false;
            }
        }

        logs("Success", httpMeta, permRolesMeta);
        return true;
    }
}
