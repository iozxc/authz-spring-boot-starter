package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.AuthzContext;
import org.springframework.lang.NonNull;

import java.util.List;
import java.util.Optional;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class AuthzStateHelper extends BaseHelper {

    private AuthzStateHelper() {
        throw new UnsupportedOperationException();
    }

    public static boolean isLogin() {
        try {
            HttpMeta    currentHttpMeta = AuthzContext.getCurrentHttpMeta();
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

    public static boolean hasRoles(@NonNull List<String> roles) {
        try {
            if (roles.isEmpty()) return true;
            return AuthzContext.getCurrentHttpMeta().getRoles().containsAll(roles);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean hasPermissions(@NonNull List<String> permissions) {
        try {
            if (permissions.isEmpty()) return true;
            return AuthzContext.getCurrentHttpMeta().getPermissions().containsAll(permissions);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean hasScope(@NonNull List<String> scope) {
        try {
            if (scope.isEmpty()) return true;
            return AuthzContext.getCurrentHttpMeta().getScope().containsAll(scope);
        } catch (Exception e) {
            return false;
        }
    }

}
