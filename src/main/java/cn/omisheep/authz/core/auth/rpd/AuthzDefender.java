package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.DefaultDevice;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.SneakyThrows;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class AuthzDefender {

    private final UserDevicesDict userDevicesDict;
    private final PermissionDict permissionDict;
    private final PermLibrary permLibrary;

    public AuthzDefender(UserDevicesDict userDevicesDict, PermissionDict permissionDict, PermLibrary permLibrary) {
        this.userDevicesDict = userDevicesDict;
        this.permissionDict = permissionDict;
        this.permLibrary = permLibrary;
    }

    /**
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备id
     * @return 授权后的tokenPair(accessToken以及refreshToken)
     */
    public TokenPair grant(Object userId, String deviceType, String deviceId) {
        TokenPair tokenPair = TokenHelper.createTokenPair(userId, deviceType, deviceId);
        HttpServletResponse response = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getResponse();
        HttpMeta httpMeta = (HttpMeta) ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest().getAttribute("AU_HTTP_META");
        if (response != null) {
            response.addCookie(TokenHelper.generateCookie(tokenPair.getAccessToken()));
        }
        DefaultDevice device = new DefaultDevice();
        device.setType(deviceType).setId(deviceId).setLastRequestTime(TimeUtils.now()).setIp(httpMeta.getIp());
        try {
            if (userDevicesDict.addUser(userId, tokenPair, device)) return tokenPair;
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
                HttpServletResponse response = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getResponse();
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

    public boolean requireProtect(String method, String api) {
        Map<String, PermRolesMeta> map = permissionDict.getAuthzMetadata().get(method);
        if (map == null) return false;
        return map.get(api) != null;
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

        if (!httpMeta.isHasTokenCookie()) {
            logs("Require Login", httpMeta, permRolesMeta);
            return ExceptionStatus.REQUIRE_LOGIN;
        }

        if (httpMeta.getTokenException() != null) {
            switch (httpMeta.getTokenException()) {
                case ExpiredJwtException:
                    logs("Forbid : expired token exception", httpMeta, permRolesMeta);
                    return ExceptionStatus.ACCESS_TOKEN_OVERDUE;
                case MalformedJwtException:
                    logs("Forbid : malformed token exception", httpMeta, permRolesMeta);
                    return ExceptionStatus.TOKEN_EXCEPTION;
                case SignatureException:
                    logs("Forbid : signature exception", httpMeta, permRolesMeta);
                    return ExceptionStatus.TOKEN_EXCEPTION;
            }
        }

        Token accessToken = httpMeta.getToken();

        switch (userDevicesDict.userStatus(accessToken.getUserId(), accessToken.getDeviceType(), accessToken.getDeviceId(), accessToken.getTokenId())) {
            case ACCESS_TOKEN_OVERDUE:
                // accessToken过期
                logs("Forbid : expired token exception", httpMeta, permRolesMeta);
                return ExceptionStatus.ACCESS_TOKEN_OVERDUE;
            case REQUIRE_LOGIN:
                // 需要重新登录
                logs("Require Login", httpMeta, permRolesMeta);
                return ExceptionStatus.REQUIRE_LOGIN;
            case LOGIN_EXCEPTION:
                // 在别处登录
                logs("forbid : may have logged in elsewhere", httpMeta, permRolesMeta);
                return ExceptionStatus.LOGIN_EXCEPTION;
        }

        Set<String> roles = null;
        boolean e1 = CollectionUtils.isEmpty(permRolesMeta.getRequireRoles());
        boolean e2 = CollectionUtils.isEmpty(permRolesMeta.getExcludeRoles());
        if (!e1 || !e2) {
            long nowTime = TimeUtils.nowTime();
            roles = permLibrary.getRolesByUserId(accessToken.getUserId());
            LogUtils.logDebug("permLibrary.getRolesByUserId({})  {}",accessToken.getUserId(), TimeUtils.diff(nowTime));
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
                LogUtils.logDebug("permLibrary.getPermissionsByRole({}) {}", role, TimeUtils.diff(nowTime));
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

    private void logs(String status, HttpMeta httpMeta, PermRolesMeta meta) {
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
