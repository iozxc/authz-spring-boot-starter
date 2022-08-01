package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.ThreadWebEnvironmentException;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.util.AUtils;
import org.springframework.lang.NonNull;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class AuthzStateHelper extends BaseHelper {

    public static boolean isLogin() {
        try {
            HttpMeta    currentHttpMeta = AUtils.getCurrentHttpMeta();
            AccessToken accessToken     = currentHttpMeta.getToken();
            if (accessToken == null) return false;
            UserDevicesDict.UserStatus userStatus = Optional.ofNullable(currentHttpMeta.getUserStatus()).orElseGet(
                    () -> {
                        UserDevicesDict.UserStatus u = userDevicesDict.userStatus(accessToken);
                        currentHttpMeta.setUserStatus(u);
                        return u;
                    });
            switch (userStatus) {
                case REQUIRE_LOGIN:
                case LOGIN_EXCEPTION:
                case ACCESS_TOKEN_OVERDUE:
                    return false;
                case SUCCESS:
                    return true;
                default:
                    return true;
            }
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean hasRoles(@NonNull List<String> roles) throws NotLoginException {
        try {
            return AUtils.getCurrentHttpMeta().getRoles().containsAll(roles);
        } catch (ThreadWebEnvironmentException e) {
            return false;
        }
    }

    public static boolean hasPermissions(@NonNull List<String> permissions) throws NotLoginException {
        try {
            return AUtils.getCurrentHttpMeta().getPermissions().containsAll(permissions);
        } catch (ThreadWebEnvironmentException e) {
            return false;
        }
    }

    public static boolean hasScope(@NonNull List<String> scope) throws NotLoginException {
        try {
            if (scope.isEmpty()) return true;
            Set<String> userScope = AUtils.getCurrentHttpMeta().getScope();
            if (userScope.isEmpty()) return false;
            return userScope.containsAll(scope);
        } catch (ThreadWebEnvironmentException e) {
            return false;
        }
    }

}
