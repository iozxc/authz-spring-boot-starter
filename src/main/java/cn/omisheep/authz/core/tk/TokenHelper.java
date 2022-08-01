package cn.omisheep.authz.core.tk;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.helper.BaseHelper;
import cn.omisheep.authz.core.oauth.AuthorizationInfo;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.UUIDBits;
import cn.omisheep.web.utils.HttpUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static cn.omisheep.authz.core.config.Constants.*;
import static io.jsonwebtoken.CompressionCodecs.GZIP;
import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static io.jsonwebtoken.SignatureAlgorithm.NONE;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.2.0
 * @since 1.0.0
 */
@SuppressWarnings("rawtypes")
public class TokenHelper extends BaseHelper {

    private static final Long      accessTime; // 存活时间,单位 ms
    private static final Long      refreshTime; // 存活时间,单位 ms
    private static final int       expire;
    private static final String    cookieName;
    private static final SecretKey secretKey;

    private static final SignatureAlgorithm alg;
    private static final CompressionCodec   codec = GZIP;
    private static final int                tokenIdBits;
    private static final String             prefix;

    private TokenHelper() {
    }

    static {
        AuthzProperties.TokenConfig token = properties.getToken();
        String                      key   = token.getKey();
        tokenIdBits = token.getTokenIdBits();
        if (key == null || key.equals("")) {
            secretKey = null;
            alg       = NONE;
        } else {
            StringBuilder stringBuilder = new StringBuilder(key);
            if (stringBuilder.length() * 8 < HS256.getMinKeyLength()) {
                while (stringBuilder.length() * 8 < HS256.getMinKeyLength()) {
                    stringBuilder.append(".");
                }
            }
            secretKey = Keys.hmacShaKeyFor(stringBuilder.toString().getBytes(StandardCharsets.UTF_8));
            alg       = HS256;
        }

        String    prefix1;
        JwsHeader jwsHeader = Jwts.jwsHeader();
        if (alg != SignatureAlgorithm.NONE) jwsHeader.setAlgorithm(alg.getValue());
        jwsHeader.setCompressionAlgorithm(codec.getAlgorithmName());
        try {
            byte[] bytes = new ObjectMapper().writeValueAsBytes(jwsHeader);
            prefix1 = Encoders.BASE64URL.encode(bytes) + ".";
        } catch (JsonProcessingException e) {
            LogUtils.error(e);
            prefix1 = "";
        }

        prefix      = prefix1;
        expire      = (int) (TimeUtils.parseTimeValue(token.getRefreshTime()) / 1000);
        cookieName  = properties.getToken().getCookieName();
        accessTime  = TimeUtils.parseTimeValue(token.getAccessTime());
        refreshTime = TimeUtils.parseTimeValue(token.getRefreshTime());
    }

    /**
     * 创建一个 TokenPair（ accessToken，refreshToken ）
     *
     * @param info AuthorizationInfo
     * @return TokenPair
     */
    public static TokenPair createTokenPair(AuthorizationInfo info) {
        return createTokenPair(info.getUserId(), null, null, info.getClientId(),
                               info.getScope(), info.getGrantType());
    }

    /**
     * 创建一个 TokenPair（ accessToken，refreshToken ）
     *
     * @param userId     用户id
     * @param deviceId   设备Id
     * @param deviceType 设备系统类型
     * @return TokenPair
     */
    public static TokenPair createTokenPair(Object userId, String deviceType, String deviceId) {
        return createTokenPair(userId, deviceType, deviceId, null, null, null);
    }

    /**
     * 创建一个 TokenPair（ accessToken，refreshToken ）
     *
     * @param userId     用户id
     * @param deviceType 设备系统类型
     * @param deviceId   设备Id
     * @param clientId   客户端id
     * @param scope      授权范围
     * @param grantType  授权类型
     * @return TokenPair
     */
    public static TokenPair createTokenPair(Object userId, String deviceType,
                                            String deviceId, String clientId,
                                            String scope, GrantType grantType) {
        LocalDateTime now = LocalDateTime.now();
        Date toAccessExpiredTime = // accessToken失效时间
                Date.from(now.plus(accessTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());
        Date toRefreshExpiredTime = // refreshToken失效时间
                Date.from(now.plus(refreshTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());
        String accessTokenId  = UUIDBits.getUUIDBits(tokenIdBits);
        String refreshTokenId = UUIDBits.getUUIDBits(tokenIdBits);
        return createTokenPair(userId, deviceType, deviceId, clientId, scope, grantType, accessTokenId, refreshTokenId,
                               toAccessExpiredTime, toRefreshExpiredTime);
    }


    /**
     * 创建一个 TokenPair（ accessToken，refreshToken ）
     *
     * @param userId               用户id
     * @param deviceType           设备系统类型
     * @param deviceId             设备Id
     * @param clientId             客户端id
     * @param scope                授权范围
     * @param grantType            授权类型
     * @param accessTokenId        accessToken id
     * @param refreshTokenId       refreshToken id
     * @param toAccessExpiredTime  accessToken过期时间
     * @param toRefreshExpiredTime refreshToken过期时间
     * @return TokenPair
     */
    public static TokenPair createTokenPair(Object userId, String deviceType, String deviceId, String clientId,
                                            String scope, GrantType grantType, String accessTokenId,
                                            String refreshTokenId,
                                            Date toAccessExpiredTime, Date toRefreshExpiredTime) {
        AccessToken accessToken = createAccessToken(userId, deviceType, deviceId, accessTokenId, refreshTokenId,
                                                    toAccessExpiredTime, grantType, clientId, scope);
        RefreshToken refreshToken = createRefreshToken(accessToken, toRefreshExpiredTime);

        return new TokenPair(accessToken, refreshToken);
    }


    private static AccessToken createAccessToken(Object userId, String deviceType, String deviceId,
                                                 String accessTokenId, String refreshTokenId, Date expiresAt,
                                                 GrantType grantType, String clientId, String scope) {
        Claims claims = Jwts.claims();
        claims.put(USER_ID, userId);

        if (clientId != null) { // oauth
            if (scope != null) claims.put(SCOPE, scope);
            if (grantType != null) claims.put(GRANT_TYPE, grantType.getType());
            claims.put(CLIENT_ID, clientId);
        } else {
            claims.put(DEVICE_ID, deviceId);
            claims.put(DEVICE_TYPE, deviceType);
        }
        claims.put(REFRESH_TOKEN_ID, refreshTokenId);
        JwtBuilder jwtBuilder = Jwts.builder().setClaims(claims) // 设置 claims
                .setId(accessTokenId).compressWith(codec).setExpiration(expiresAt);
        if (secretKey != null) {
            jwtBuilder.signWith(secretKey, alg);
        }
        String tokenVal = jwtBuilder.compact();
        return new AccessToken(tokenVal.substring(tokenVal.indexOf(".") + 1), accessTokenId, refreshTokenId,
                               (int) Math.min(accessTime / 1000, Integer.MAX_VALUE),
                               expiresAt.getTime(), grantType, clientId, scope, userId, deviceType, deviceId);
    }

    private static RefreshToken createRefreshToken(AccessToken accessToken, Date expiresAt) {
        Claims claims = Jwts.claims();
        claims.put(USER_ID, accessToken.getUserId());
        claims.put(CLIENT_ID, accessToken.getClientId());
        JwtBuilder jwtBuilder = Jwts.builder().setClaims(claims) // 设置 claims
                .setId(accessToken.getRefreshTokenId()).setExpiration(expiresAt).compressWith(codec);
        if (secretKey != null) {
            jwtBuilder.signWith(secretKey, alg);
        }
        String tokenVal = jwtBuilder.compact();
        return new RefreshToken(tokenVal.substring(tokenVal.indexOf(".") + 1), accessToken.getRefreshTokenId(),
                                (int) Math.min(refreshTime / 1000, Integer.MAX_VALUE), expiresAt.getTime(),
                                accessToken.getUserId(), accessToken.getClientId());
    }

    /**
     * 利用RefreshToken刷新，获得新到 accessToken和新的refreshToken，refreshToken只能使用一次，
     * 使用之后将会获得新的，新的和老的除了id和value之外，其他的如过期时间和效果等都一样
     *
     * @param refreshToken refreshToken
     * @return TokenPair
     * @throws Exception e
     */
    public static TokenPair refreshToken(String refreshToken) throws Exception {
        return refreshToken(parseRefreshToken(refreshToken));
    }

    /**
     * 利用RefreshToken刷新，获得新到 accessToken和新的refreshToken，refreshToken只能使用一次，
     * 使用之后将会获得新的，新的和老的除了id和value之外，其他的如过期时间和效果等都一样
     *
     * @param refreshToken refreshToken
     * @return TokenPair
     */
    public static TokenPair refreshToken(RefreshToken refreshToken) {
        if (refreshToken == null) return null;

        String clientId = refreshToken.getClientId();

        Device device;
        if (clientId == null) {
            device = cache.get(
                    USER_DEVICE_KEY_PREFIX.get() + refreshToken.getUserId() + SEPARATOR + refreshToken.getTokenId(),
                    Device.class);

        } else {
            device = cache.get(
                    OAUTH_USER_DEVICE_KEY_PREFIX.get() + refreshToken.getUserId() + SEPARATOR + refreshToken.getTokenId(),
                    Device.class);
        }

        if (device == null) return null;

        LocalDateTime now = LocalDateTime.now();
        Date toAccessExpiredTime = // accessToken失效时间
                Date.from(now.plus(accessTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());

        return createTokenPair(refreshToken.getUserId(), device.getDeviceType(), device.getDeviceId(),
                               device.getClientId(), device.getScope(), device.getGrantType(),
                               device.getAccessTokenId(), refreshToken.getTokenId(), toAccessExpiredTime,
                               new Date(refreshToken.getExpiredAt()));
    }

    /**
     * 根据Token生成一个Cookie
     *
     * @param token 目标Token
     * @return Cookie
     */
    public static Cookie generateCookie(AccessToken token) {
        if (token == null) return null;
        Cookie cookie = new Cookie(cookieName, token.getToken());
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(expire);
        return cookie;
    }

    /**
     * 清空cookie
     *
     * @param response response
     */
    public static void clearCookie(HttpServletResponse response) {
        if (response == null) return;
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    /**
     * 清空cookie
     */
    public static void clearCookie() {
        clearCookie(HttpUtils.getCurrentResponse());
    }

    private static Claims parseToken(String val) {
        if (val == null || val.equals("")) return null;
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(prefix + val).getBody();
    }

    /**
     * 根据tokenVal解析生成AccessToken
     *
     * @param accessToken accessToken
     * @return AccessToken
     * @throws Exception e
     */
    public static AccessToken parseAccessToken(String accessToken) throws Exception {
        Claims claims = parseToken(accessToken);
        if (claims == null || claims.get(REFRESH_TOKEN_ID, String.class) == null) {
            throw new AuthzException(ExceptionStatus.TOKEN_EXCEPTION);
        }
        return new AccessToken(accessToken, claims.getId(), claims.get(REFRESH_TOKEN_ID, String.class), null,
                               claims.getExpiration().getTime(),
                               GrantType.grantType(claims.get(GRANT_TYPE, String.class)),
                               claims.get(CLIENT_ID, String.class), claims.get(SCOPE, String.class),
                               claims.get(USER_ID), claims.get(DEVICE_TYPE, String.class),
                               claims.get(DEVICE_ID, String.class));
    }

    /**
     * 根据tokenVal解析生成AccessToken
     *
     * @param refreshToken refreshToken
     * @return AccessToken
     * @throws Exception e
     */
    public static RefreshToken parseRefreshToken(String refreshToken) throws Exception {
        Claims claims = parseToken(refreshToken);
        if (claims == null) {
            throw new AuthzException(ExceptionStatus.TOKEN_EXCEPTION);
        }
        return new RefreshToken(refreshToken, claims.getId(),
                                null,
                                claims.getExpiration().getTime(),
                                claims.get(USER_ID),
                                claims.get(CLIENT_ID, String.class));
    }

}
