package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.ThreadWebEnvironmentException;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.web.utils.HttpUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuthzDefender {

    private static UserDevicesDict userDevicesDict;
    private static PermLibrary     permLibrary;

    public static void init(UserDevicesDict userDevicesDict, PermLibrary permLibrary) {
        if (AuthzDefender.userDevicesDict == null) {
            AuthzDefender.userDevicesDict = userDevicesDict;
        }

        if (AuthzDefender.permLibrary == null) {
            AuthzDefender.permLibrary = permLibrary;
        }
    }

    /**
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备id
     * @return 授权后的tokenPair(accessToken, refreshToken)
     */
    public static TokenPair grant(Object userId, String deviceType, String deviceId) {
        TokenPair tokenPair = TokenHelper.createTokenPair(userId, deviceType, deviceId);
        if (grant(tokenPair)) return tokenPair;
        return null;
    }

    /**
     * @param tokenPair tokenPair 某种途径生成的tokenPair
     * @return 登录是否成功
     */
    public static boolean grant(TokenPair tokenPair) {
        if (tokenPair == null) return false;
        HttpServletResponse response = HttpUtils.getCurrentResponse();
        try {
            HttpMeta httpMeta    = AUtils.getCurrentHttpMeta();
            Token    accessToken = tokenPair.getAccessToken();
            if (response != null) {
                response.addCookie(TokenHelper.generateCookie(accessToken));
            }
            if (userDevicesDict.addUser(accessToken.getUserId(), tokenPair, accessToken.getDeviceType(),
                                        accessToken.getDeviceId(), httpMeta)) return true;
            else return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * access过期刷新接口
     * 如果使用单token，则直接使用accessToken即可，在accessToken过期时再重新登录。
     * 使用双token时，accessToken过期时，可以利用refreshToken在此接口中刷新获得一个新的accessToken。
     *
     * @param refreshToken 与accessToken一起授予的refreshToken
     * @return 刷新成功（Token）/ 失败（null）
     */
    public static TokenPair refreshToken(String refreshToken) {
        try {
            TokenPair tokenPair = TokenHelper.refreshToken(refreshToken);
            if (userDevicesDict.refreshUser(tokenPair)) {
                HttpServletResponse response = HttpUtils.getCurrentResponse();
                if (response != null) {
                    response.addCookie(TokenHelper.generateCookie(tokenPair.getAccessToken()));
                }
                return tokenPair;
            }
            return null;
        } catch (ExpiredJwtException e) {
            return null;
        }
    }

    public static void clearCookie() {
        TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
    }

    public static void clearCookie(Object userId) {
        if (userId == null) {
            TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
        } else {
            Token token = AUtils.getCurrentToken();
            if (token == null) return;
            if (ObjectUtils.equals(token.getUserId(), userId)) TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
        }
    }

    public static void clearCookie(Object userId, String deviceType) {
        Token token = AUtils.getCurrentToken();
        if (token == null) return;
        if (userId == null) userId = token.getUserId();
        if (ObjectUtils.equals(token.getUserId(), userId) && StringUtils.equals(token.getDeviceType(),
                                                                                deviceType)) clearCookie(userId);
    }

    public static void clearCookie(Object userId, String deviceType, String deviceId) {
        Token token = AUtils.getCurrentToken();
        if (token == null) return;
        if (userId == null) userId = token.getUserId();
        if (ObjectUtils.equals(token.getUserId(), userId) && StringUtils.equals(token.getDeviceType(),
                                                                                deviceType) && StringUtils.equals(
                token.getDeviceId(), deviceId)) clearCookie();
    }

    public static void logout() {
        userDevicesDict.removeCurrentDeviceFromCurrentUser();
        clearCookie(null);
    }

    public static void logoutAll() {
        userDevicesDict.removeAllDeviceFromCurrentUser();
        clearCookie(null);
    }

    public static void logout(@NonNull String deviceType) {
        userDevicesDict.removeDeviceFromCurrentUserByDeviceType(deviceType);
        clearCookie(null, deviceType);
    }

    public static void logout(@NonNull String deviceType, @Nullable String deviceId) {
        userDevicesDict.removeDeviceFromCurrentUserByDeviceTypeAndDeviceId(deviceType, deviceId);
        clearCookie(null, deviceType, deviceType);
    }

    public static void logoutAll(@NonNull Object userId) {
        userDevicesDict.removeAllDeviceByUserId(userId);
        clearCookie(userId);
    }

    public static void logout(@NonNull Object userId, @NonNull String deviceType) {
        userDevicesDict.removeDeviceByUserIdAndDeviceType(userId, deviceType);
        clearCookie(userId, deviceType);
    }

    public static void logout(@NonNull Object userId, @NonNull String deviceType, @Nullable String deviceId) {
        userDevicesDict.removeDeviceByUserIdAndDeviceTypeAndDeviceId(userId, deviceType, deviceId);
        clearCookie(userId, deviceType, deviceId);
    }

    public static boolean isLogin() {
        try {
            HttpMeta currentHttpMeta = AUtils.getCurrentHttpMeta();
            Token    accessToken     = currentHttpMeta.getToken();
            if (accessToken == null) return false;
            switch (userDevicesDict.userStatus(accessToken)) {
                case ACCESS_TOKEN_OVERDUE:
                case REQUIRE_LOGIN:
                case LOGIN_EXCEPTION:
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
        Set<String> r = null;
        try {
            HttpMeta httpMeta = AUtils.getCurrentHttpMeta();
            r = Optional.ofNullable(httpMeta.getRoles()).orElse(permLibrary.getRolesByUserId(httpMeta.getUserId()));
        } catch (ThreadWebEnvironmentException e) {
            return false;
        }
        if (r == null) return false;
        return r.containsAll(roles);
    }

    public static boolean hasPermissions(@NonNull List<String> permissions) throws NotLoginException {
        Set<String> p = null;
        try {
            HttpMeta httpMeta = AUtils.getCurrentHttpMeta();
            p = Optional.ofNullable(httpMeta.getPermissions()).orElseGet(() -> {
                HashSet<String> perms = new HashSet<>();
                Set<String> r = Optional.ofNullable(httpMeta.getRoles()).orElse(
                        permLibrary.getRolesByUserId(httpMeta.getUserId()));
                r.forEach(role -> perms.addAll(permLibrary.getPermissionsByRole(role)));
                return perms;
            });
        } catch (ThreadWebEnvironmentException e) {
            return false;
        }
        if (p == null) return false;
        return p.containsAll(permissions);
    }

    public static void logs(String status, HttpMeta httpMeta, PermRolesMeta meta) {
        Token token = httpMeta.getToken();
        if (token == null) {
            httpMeta.log("「{}」\t{}", status, meta);
        } else {
            httpMeta.log("「{}」\t\t{}\t, userId: [{}]\t, deviceType = [{}]\t, deviceId = [{}]",
                         status, meta, token.getUserId(), token.getDeviceType(), token.getDeviceId());
        }
    }

    public static void logs(String status, HttpMeta httpMeta) {
        Token token = httpMeta.getToken();
        if (token == null) {
            httpMeta.log("「{}」", status);
        } else {
            httpMeta.log("「{}」\t, userId: [{}]\t, deviceType = [{}]\t, deviceId = [{}]",
                         status, token.getUserId(), token.getDeviceType(), token.getDeviceId());
        }
    }

}
