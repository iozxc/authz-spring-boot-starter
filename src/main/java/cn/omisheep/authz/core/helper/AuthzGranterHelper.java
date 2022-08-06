package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.*;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.*;
import cn.omisheep.authz.core.AuthzContext;
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

    private AuthzGranterHelper() {
        throw new UnsupportedOperationException();
    }

    /**
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备id
     * @return 授权后的tokenPair(accessToken, refreshToken)
     */
    public static IssueToken grant(Object userId,
                                   String deviceType,
                                   String deviceId) {
        TokenPair tokenPair = TokenHelper.createTokenPair(userId, deviceType, deviceId);
        if (grant(tokenPair, true)) return TokenHelper.createIssueToken(tokenPair);
        return null;
    }

    public static IssueToken grant(Object userId) {
        String deviceType;
        try {
            deviceType = AuHelper.getHttpMeta().getUserAgent();
        } catch (ThreadWebEnvironmentException e) {
            deviceType = "unknown";
        }
        return grant(userId, deviceType, null);
    }

    /**
     * @param tokenPair tokenPair 某种途径生成的tokenPair
     * @param resp      保存于cookie / 不缓存
     * @return 登录是否成功
     */
    public static boolean grant(TokenPair tokenPair,
                                boolean resp) {
        if (tokenPair == null) return false;
        try {
            HttpMeta            httpMeta    = AuthzContext.getCurrentHttpMeta();
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
                return TokenHelper.createIssueToken(tokenPair);
            }
            return null;
        } catch (ExpiredJwtException e) {
            throw new RefreshTokenExpiredException();
        } catch (Exception e) {
            throw new AuthzException(ExceptionStatus.TOKEN_EXCEPTION);
        }
    }

    public static void clearCookie() {
        TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
    }

    public static void clearCookie(Object userId) {
        if (userId == null) {
            TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
        } else {
            AccessToken token = AuthzContext.getCurrentToken();
            if (token == null) return;
            if (ObjectUtils.equals(token.getUserId(), userId)) TokenHelper.clearCookie(HttpUtils.getCurrentResponse());
        }
    }

    public static void clearCookie(Object userId,
                                   String deviceType) {
        AccessToken token = AuthzContext.getCurrentToken();
        if (token == null) return;
        if (userId == null) userId = token.getUserId();
        if (ObjectUtils.equals(token.getUserId(), userId) && StringUtils.equals(token.getDeviceType(),
                                                                                deviceType)) {clearCookie(userId);}
    }

    public static void clearCookie(Object userId,
                                   String deviceType,
                                   String deviceId) {
        AccessToken token = AuthzContext.getCurrentToken();
        if (token == null) return;
        if (userId == null) userId = token.getUserId();
        if (ObjectUtils.equals(token.getUserId(), userId) && StringUtils.equals(token.getDeviceType(),
                                                                                deviceType) && StringUtils.equals(
                token.getDeviceId(), deviceId)) {clearCookie();}
    }

    public static void logout() {
        userDevicesDict.removeCurrentDevice();
        clearCookie(null);
    }

    public static void logoutAll() {
        try {
            userDevicesDict.removeAllDevice(AuHelper.getUserId());
            clearCookie(null);
        } catch (Exception e) {
            // skip
        }
    }

    public static void logout(@NonNull String deviceType) {
        try {
            userDevicesDict.removeDevice(AuHelper.getUserId(), deviceType, null);
            clearCookie(null, deviceType);
        } catch (Exception e) {
            // skip
        }
    }

    public static void logout(@NonNull String deviceType,
                              @Nullable String deviceId) {
        try {
            userDevicesDict.removeDevice(AuHelper.getUserId(), deviceType, deviceId);
            clearCookie(null, deviceType, deviceType);
        } catch (Exception e) {
            // skip
        }
    }

    public static void logoutAll(@NonNull Object userId) {
        userDevicesDict.removeAllDevice(userId);
        clearCookie(userId);
    }

    public static void logout(@NonNull Object userId,
                              @NonNull String deviceType) {
        userDevicesDict.removeDevice(userId, deviceType, null);
        clearCookie(userId, deviceType);
    }

    public static void logout(@NonNull Object userId,
                              @NonNull String deviceType,
                              @Nullable String deviceId) {
        userDevicesDict.removeDevice(userId, deviceType, deviceId);
        clearCookie(userId, deviceType, deviceId);
    }

}
