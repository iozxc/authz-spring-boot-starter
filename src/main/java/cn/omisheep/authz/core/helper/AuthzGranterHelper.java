package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.*;
import cn.omisheep.authz.core.tk.*;
import cn.omisheep.web.utils.HttpUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import javax.servlet.http.HttpServletResponse;

public class AuthzGranterHelper extends BaseHelper {

    private AuthzGranterHelper() {
        throw new UnsupportedOperationException();
    }

    /**
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备id
     * @return 授权后的IssueToken(accessToken, refreshToken)
     */
    public static IssueToken grant(Object userId,
                                   String deviceType,
                                   String deviceId) {
        if (deviceType == null) {
            try {
                deviceType = AuHelper.getHttpMeta().getUserAgent();
            } catch (ThreadWebEnvironmentException e) {
                deviceType = "unknown";
            }
        }
        TokenPair tokenPair = TokenHelper.createTokenPair(userId, deviceType, deviceId);
        grant(tokenPair, true);
        return TokenHelper.createIssueToken(tokenPair);
    }

    /**
     * @param tokenPair tokenPair 某种途径生成的tokenPair
     * @param resp      保存于cookie / 不缓存
     */
    public static void grant(TokenPair tokenPair,
                             boolean resp) {
        userDevicesDict.addUser(tokenPair, AuthzContext.getCurrentHttpMeta());
        try {
            HttpServletResponse response = HttpUtils.currentResponse.get();
            if (response != null) {
                if (resp) {
                    response.addCookie(TokenHelper.generateCookie(tokenPair.getAccessToken()));
                } else {
                    response.setHeader("pragma", "no-cache");
                    response.setHeader("cache-control", "no-cache");
                    response.setDateHeader("expires", 0);
                }
            }
        } catch (Exception e) {
            // skip
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
     * @return IssueToken
     * @throws RefreshTokenExpiredException refreshToken过期
     * @throws TokenException               refreshToken异常
     */
    public static IssueToken refreshToken(String refreshToken) throws RefreshTokenExpiredException,
            TokenException {
        try {
            if (refreshToken == null) {
                throw new TokenException();
            }
            TokenPair tokenPair = TokenHelper.refreshToken(refreshToken);
            if (userDevicesDict.refreshUser(tokenPair)) {
                try {
                    HttpServletResponse response = HttpUtils.currentResponse.get();
                    if (response != null) {
                        response.addCookie(TokenHelper.generateCookie(tokenPair.getAccessToken()));
                    }
                } catch (Exception e) {
                    // skip
                }
                return TokenHelper.createIssueToken(tokenPair);
            } else {
                throw new RefreshTokenExpiredException();
            }
        } catch (ExpiredJwtException e) {
            throw new RefreshTokenExpiredException();
        } catch (Exception e) {
            throw new TokenException();
        }
    }

    public static void clearCookie(Object userId,
                                   String deviceType,
                                   String deviceId) {
        try {
            AccessToken token = AuthzContext.getCurrentToken();
            if (userId == null) userId = token.getUserId();
            if (ObjectUtils.equals(token.getUserId(), userId)
                    && (deviceType == null || StringUtils.equals(token.getDeviceType(), deviceType))
                    && (deviceId == null || StringUtils.equals(token.getDeviceId(), deviceId))) {
                TokenHelper.clearCookie(HttpUtils.currentResponse.get());
            }
        } catch (Exception e) {
            // skip
        }
    }

    public static void logoutById(Object userId,
                                  String id) {
        userDevicesDict.removeDeviceById(userId, id);
        clearCookie(userId, null, null);
    }

    public static void logout() throws NotLoginException {
        AuHelper.getToken();
        userDevicesDict.removeCurrentDevice();
        clearCookie(null, null, null);
    }

    public static void logoutAll() throws NotLoginException {
        userDevicesDict.removeAllDevice(AuHelper.getUserId());
        clearCookie(null, null, null);
    }

    public static void logout(@NonNull String deviceType,
                              @Nullable String deviceId) throws NotLoginException {
        userDevicesDict.removeDevice(AuHelper.getUserId(), deviceType, deviceId);
        clearCookie(null, deviceType, deviceId);
    }

    public static void logoutAll(@NonNull Object userId) {
        userDevicesDict.removeAllDevice(userId);
        clearCookie(userId, null, null);
    }

    public static void logout(@NonNull Object userId,
                              @NonNull String deviceType) {
        userDevicesDict.removeDevice(userId, deviceType, null);
        clearCookie(userId, deviceType, null);
    }

    public static void logout(@NonNull Object userId,
                              @NonNull String deviceType,
                              @Nullable String deviceId) {
        userDevicesDict.removeDevice(userId, deviceType, deviceId);
        clearCookie(userId, deviceType, deviceId);
    }

}
