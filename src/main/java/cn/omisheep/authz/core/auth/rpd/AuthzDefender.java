package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.init.AuInit;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.web.utils.HttpUtils;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.SneakyThrows;

import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class AuthzDefender {

    private static AuthzDefender SELF;

    public static AuthzDefender self() {
        return SELF;
    }

    private final UserDevicesDict userDevicesDict;
    private final PermissionDict permissionDict;
    private final PermLibrary permLibrary;

    public AuthzDefender(UserDevicesDict userDevicesDict, PermissionDict permissionDict, PermLibrary permLibrary) {
        this.userDevicesDict = userDevicesDict;
        this.permissionDict = permissionDict;
        this.permLibrary = permLibrary;
    }

    public static void init(AuthzDefender authzDefender) {
        if (SELF != null) {
            AuInit.log.error("authzDefender 已经初始化");
            return;
        }
        SELF = authzDefender;
    }

    /**
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备id
     * @return 授权后的tokenPair(accessToken以及refreshToken)
     */
    public TokenPair grant(Object userId, String deviceType, String deviceId) {
        TokenPair tokenPair = TokenHelper.createTokenPair(userId, deviceType, deviceId);

        HttpServletResponse response = HttpUtils.getCurrentResponse();
        HttpMeta httpMeta = (HttpMeta) HttpUtils.getCurrentRequest().getAttribute("AU_HTTP_META");
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
    public TokenPair refreshToken(String refreshToken) {
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

    /**
     * 合法性判断
     *
     * @param httpMeta httpMeta
     * @return 合法性判断
     */
    @SneakyThrows
    @SuppressWarnings("all")
    public ExceptionStatus verify(HttpMeta httpMeta) {
        PermRolesMeta permRolesMeta = permissionDict.getAuthzMetadata().get(httpMeta.getMethod()).get(httpMeta.getApi());
        Token accessToken = httpMeta.getToken();

        Set<String> roles = null;
        boolean e1 = CollectionUtils.isEmpty(permRolesMeta.getRequireRoles());
        boolean e2 = CollectionUtils.isEmpty(permRolesMeta.getExcludeRoles());
        if (!e1 || !e2) {
            long nowTime = TimeUtils.nowTime();
            roles = permLibrary.getRolesByUserId(accessToken.getUserId());
            LogUtils.logDebug("permLibrary.getRolesByUserId({})  {}", accessToken.getUserId(), TimeUtils.diff(nowTime)); // todo: 减少耗时
            if (!e1 && !CollectionUtils.containsSub(permRolesMeta.getRequireRoles(), roles) || !e2 && CollectionUtils.containsSub(permRolesMeta.getExcludeRoles(), roles)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                return ExceptionStatus.PERM_EXCEPTION;
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
                LogUtils.logDebug("permLibrary.getPermissionsByRole({}) {}", role, TimeUtils.diff(nowTime)); // todo: 减少耗时
                if (permissionsByRole != null) {
                    perms.addAll(permissionsByRole);
                }
                if (!e4 && CollectionUtils.containsSub(permRolesMeta.getExcludePermissions(), permissionsByRole)) {
                    logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                    return ExceptionStatus.PERM_EXCEPTION;
                }
            }
            if (!e3 && !CollectionUtils.containsSub(permRolesMeta.getRequirePermissions(), perms)) {
                logs("Forbid : permissions exception", httpMeta, permRolesMeta);
                return ExceptionStatus.PERM_EXCEPTION;
            }
        }

        logs("Success", httpMeta, permRolesMeta);
        return null;
    }

    public static void logs(String status, HttpMeta httpMeta, PermRolesMeta meta) {
        Token token = httpMeta.getToken();
        if (token == null) {
            LogUtils.pushLogToRequest("「{}」\t{}",
                    status, meta);
        } else {
            LogUtils.pushLogToRequest("「{}」\t\t{}\t, userId: [{}]\t, deviceType&deviceId [ {} , {} ]",
                    status, meta, token.getUserId(), token.getDeviceType(), token.getDeviceId());
        }
    }


}
