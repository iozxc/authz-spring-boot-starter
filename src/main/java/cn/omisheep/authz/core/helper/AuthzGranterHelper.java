package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.core.RefreshTokenExpiredException;
import cn.omisheep.authz.core.ThreadWebEnvironmentException;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.*;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.web.utils.HttpUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuthzGranterHelper extends BaseHelper {

    /**
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备id
     * @return 授权后的tokenPair(accessToken, refreshToken)
     */
    public static IssueToken grant(Object userId, String deviceType, String deviceId) {
        TokenPair tokenPair = TokenHelper.createTokenPair(userId, deviceType, deviceId);
        if (grant(tokenPair, true)) return new IssueToken(tokenPair);
        return null;
    }

    /**
     * @param tokenPair tokenPair 某种途径生成的tokenPair
     * @param resp      保存于cookie / 不缓存
     * @return 登录是否成功
     */
    public static boolean grant(TokenPair tokenPair, boolean resp) {
        if (tokenPair == null) return false;
        try {
            HttpMeta            httpMeta    = AUtils.getCurrentHttpMeta();
            AccessToken         accessToken = tokenPair.getAccessToken();
            HttpServletResponse response    = HttpUtils.getCurrentResponse();
            if (response != null) {
                if (resp) {
                    response.addCookie(TokenHelper.generateCookie(accessToken));
                } else {
                    response.setHeader("pragma", "no-cache");
                    response.setHeader("cache-control", "no-cache");
                    response.setDateHeader("expires", 0);
                }
            }
            userDevicesDict.addUser(tokenPair, httpMeta);
            return true;
        } catch (ThreadWebEnvironmentException e) {
            return false;
        }
    }

    /**
     * access过期刷新接口
     * 1、利用RefreshToken刷新，获得新到 accessToken和新的refreshToken，refreshToken只能使用一次，
     * 使用之后将会获得新的，新的和老的除了id和value之外，其他的如过期时间和效果等都一样。
     * <p>
     * 2、如果使用单token，则直接使用accessToken即可，在accessToken过期时再重新登录。
     *
     * @param refreshToken 与accessToken一起授予的refreshToken
     * @return 刷新成功（TokenPair）/ 失败（null）
     */
    public static IssueToken refreshToken(String refreshToken) throws RefreshTokenExpiredException {
        try {
            RefreshToken refresh   = TokenHelper.parseRefreshToken(refreshToken);
            TokenPair    tokenPair = TokenHelper.refreshToken(refresh);
            if (userDevicesDict.refreshUser(refresh, tokenPair)) {
                HttpServletResponse response = HttpUtils.getCurrentResponse();
                if (response != null) {
                    response.addCookie(TokenHelper.generateCookie(tokenPair.getAccessToken()));
                }
                return new IssueToken(tokenPair);
            }
            return null;
        } catch (ExpiredJwtException e) {
            throw new RefreshTokenExpiredException();
        }
    }

    public static void clearCookie() {
        TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
    }

    public static void clearCookie(Object userId) {
        if (userId == null) {
            TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
        } else {
            AccessToken token = AUtils.getCurrentToken();
            if (token == null) return;
            if (ObjectUtils.equals(token.getUserId(), userId)) TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
        }
    }

    public static void clearCookie(Object userId, String deviceType) {
        AccessToken token = AUtils.getCurrentToken();
        if (token == null) return;
        if (userId == null) userId = token.getUserId();
        if (ObjectUtils.equals(token.getUserId(), userId) && StringUtils.equals(token.getDeviceType(),
                                                                                deviceType)) clearCookie(userId);
    }

    public static void clearCookie(Object userId, String deviceType, String deviceId) {
        AccessToken token = AUtils.getCurrentToken();
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

}
