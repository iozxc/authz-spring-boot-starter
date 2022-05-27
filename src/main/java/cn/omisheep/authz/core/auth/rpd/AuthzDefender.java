package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.init.AuInit;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.web.utils.HttpUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class AuthzDefender {

    private static UserDevicesDict userDevicesDict;

    public static void init(UserDevicesDict userDevicesDict) {
        if (AuthzDefender.userDevicesDict != null) {
            AuInit.log.error("authzDefender 已经初始化");
            return;
        }
        AuthzDefender.userDevicesDict = userDevicesDict;
    }

    /**
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备id
     * @return 授权后的tokenPair(accessToken以及refreshToken)
     */
    public static TokenPair grant(Object userId, String deviceType, String deviceId) {
        TokenPair tokenPair = TokenHelper.createTokenPair(userId, deviceType, deviceId);

        HttpServletResponse response = HttpUtils.getCurrentResponse();
        HttpMeta            httpMeta = AUtils.getCurrentHttpMeta();
        if (response != null) {
            response.addCookie(TokenHelper.generateCookie(tokenPair.getAccessToken()));
        }
        try {
            if (userDevicesDict.addUser(userId, tokenPair, deviceType, deviceId, httpMeta)) return tokenPair;
            else return null;
        } catch (Exception e) {
            return null;
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
        if (ObjectUtils.equals(token.getUserId(), userId) && StringUtils.equals(token.getDeviceType(), deviceType)) clearCookie(userId);
    }

    public static void clearCookie(Object userId, String deviceType, String deviceId) {
        Token token = AUtils.getCurrentToken();
        if (token == null) return;
        if (userId == null) userId = token.getUserId();
        if (ObjectUtils.equals(token.getUserId(), userId) && StringUtils.equals(token.getDeviceType(), deviceType) && StringUtils.equals(token.getDeviceId(), deviceId)) clearCookie();
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

    public static void logs(String status, HttpMeta httpMeta, PermRolesMeta meta) {
        Token token = httpMeta.getToken();
        if (token == null) {
            LogUtils.pushLogToRequest("「{}」\t{}",
                    status, meta);
        } else {
            LogUtils.pushLogToRequest("「{}」\t\t{}\t, userId: [{}]\t, deviceType = {}\t, deviceId = {}",
                    status, meta, token.getUserId(), token.getDeviceType(), token.getDeviceId());
        }
    }

    public static void logs(String status, HttpMeta httpMeta) {
        Token token = httpMeta.getToken();
        if (token == null) {
            LogUtils.pushLogToRequest("「{}」", status);
        } else {
            LogUtils.pushLogToRequest("「{}」\t, userId: [{}]\t, deviceType = {}\t, deviceId = {}",
                    status, token.getUserId(), token.getDeviceType(), token.getDeviceId());
        }
    }

}
