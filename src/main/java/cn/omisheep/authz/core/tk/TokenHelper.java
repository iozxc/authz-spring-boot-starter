package cn.omisheep.authz.core.tk;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.TokenException;
import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.helper.BaseHelper;
import cn.omisheep.authz.core.oauth.AuthorizationInfo;
import cn.omisheep.authz.core.util.HttpUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.UUIDBits;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
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
        throw new UnsupportedOperationException();
    }

    static {
        AuthzProperties.TokenConfig token = properties.getToken();
        String                      key   = token.getKey();
        tokenIdBits = token.getIdBits();
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
        cookieName  = properties.getToken().getCookieName();
        accessTime  = TimeUtils.parseTimeValue(token.getAccessTime());
        refreshTime = TimeUtils.parseTimeValue(token.getRefreshTime());
        expire      = (int) (accessTime / 1000);
    }

    public static boolean hasKey() {
        return secretKey != null;
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
    public static TokenPair createTokenPair(Object userId,
                                            String deviceType,
                                            String deviceId) {
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
    public static TokenPair createTokenPair(Object userId,
                                            String deviceType,
                                            String deviceId,
                                            String clientId,
                                            String scope,
                                            GrantType grantType) {
        Date now                  = TimeUtils.now();
        Date toAccessExpiredTime  = TimeUtils.datePlus(now, accessTime);
        Date toRefreshExpiredTime = TimeUtils.datePlus(now, refreshTime);

        String id            = UUIDBits.getUUIDBits(tokenIdBits);
        String accessTokenId = UUIDBits.getUUIDBits(tokenIdBits);
        return createTokenPair(userId, deviceType, deviceId, clientId, scope, grantType,
                               accessTokenId, id,
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
     * @param id                   id
     * @param toAccessExpiredTime  accessToken过期时间
     * @param toRefreshExpiredTime refreshToken过期时间
     * @return TokenPair
     */
    public static TokenPair createTokenPair(Object userId,
                                            String deviceType,
                                            String deviceId,
                                            String clientId,
                                            String scope,
                                            GrantType grantType,
                                            String accessTokenId,
                                            String id,
                                            Date toAccessExpiredTime,
                                            Date toRefreshExpiredTime) {
        AccessToken accessToken = createAccessToken(userId, deviceType, deviceId, accessTokenId, id,
                                                    toAccessExpiredTime, clientId, scope, grantType);
        RefreshToken refreshToken = createRefreshToken(accessToken, toRefreshExpiredTime);

        return new TokenPair(accessToken, refreshToken);
    }


    private static AccessToken createAccessToken(Object userId,
                                                 String deviceType,
                                                 String deviceId,
                                                 String accessTokenId,
                                                 String id,
                                                 Date expiresAt,
                                                 String clientId,
                                                 String scope,
                                                 GrantType grantType) {
        Claims claims = Jwts.claims();
        claims.put(USER_ID, userId);
        claims.put(ID, id);

        if (clientId != null) { // oauth
            if (grantType != null) claims.put(GRANT_TYPE, grantType.getType());
            if (scope != null) claims.put(SCOPE, scope);
            claims.put(CLIENT_ID, clientId);
        } else {
            claims.put(DEVICE_ID, deviceId);
            claims.put(DEVICE_TYPE, deviceType);
        }

        JwtBuilder jwtBuilder = Jwts.builder().setClaims(claims) // 设置 claims
                .setId(accessTokenId).compressWith(codec).setExpiration(expiresAt);
        if (hasKey()) {
            jwtBuilder.signWith(secretKey, alg);
        }
        String tokenVal = jwtBuilder.compact();
        return new AccessToken(id, tokenVal.substring(tokenVal.indexOf(".") + 1), accessTokenId,
                               accessTime,
                               expiresAt.getTime(), grantType, clientId, scope, userId, deviceType, deviceId);
    }

    private static RefreshToken createRefreshToken(AccessToken accessToken,
                                                   Date expiresAt) {
        Claims claims = Jwts.claims();
        claims.put(USER_ID, accessToken.getUserId());
        claims.put(CLIENT_ID, accessToken.getClientId());
        JwtBuilder jwtBuilder = Jwts.builder().setClaims(claims) // 设置 claims
                .setId(accessToken.getId()).setExpiration(expiresAt).compressWith(codec);
        if (hasKey()) {
            jwtBuilder.signWith(secretKey, alg);
        }
        String tokenVal = jwtBuilder.compact();
        return new RefreshToken(accessToken.getId(), tokenVal.substring(tokenVal.indexOf(".") + 1),
                                refreshTime, expiresAt.getTime(),
                                accessToken.getUserId(), accessToken.getClientId());
    }

    /**
     * 利用RefreshToken刷新，获得新到 accessToken和新的refreshToken，refreshToken只能使用一次，
     * 使用之后将会获得新的，新的和老的除了id和value之外，其他的如过期时间和效果等都一样
     *
     * @param refreshToken refreshToken
     * @return TokenPair
     * @throws TokenException e
     */
    public static TokenPair refreshToken(String refreshToken) throws TokenException {
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
                    USER_DEVICE_KEY_PREFIX.get() + refreshToken.getUserId() + SEPARATOR + refreshToken.getId(),
                    Device.class);

        } else {
            device = cache.get(
                    OAUTH_USER_DEVICE_KEY_PREFIX.get() + refreshToken.getUserId() + SEPARATOR + refreshToken.getId(),
                    Device.class);
        }

        if (device == null) return null;

        LocalDateTime now = LocalDateTime.now();
        Date toAccessExpiredTime = // accessToken失效时间
                Date.from(now.plus(accessTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());

        return createTokenPair(refreshToken.getUserId(), device.getDeviceType(), device.getDeviceId(),
                               device.getClientId(), device.getScope(), device.getGrantType(),
                               device.getAccessTokenId(), refreshToken.getId(), toAccessExpiredTime,
                               new Date(refreshToken.getExpiresAt()));
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
     */
    public static void clearCookie() {
        if (HttpUtils.currentResponse.get() == null) {
            return;
        }
        Cookie cookie = HttpUtils.readSingleCookieInRequestByName(cookieName);
        if (cookie != null) {
            cookie.setMaxAge(0);
        }
        HttpUtils.currentResponse.get().addCookie(cookie);
    }

    private static Claims parseToken(String val) {
        if (val == null || val.equals("")) return null;
        JwtParserBuilder jwtParserBuilder = Jwts.parserBuilder();
        if (hasKey()) jwtParserBuilder.setSigningKey(secretKey);
        return jwtParserBuilder.build().parseClaimsJws(prefix + val).getBody();
    }

    /**
     * 根据tokenVal解析生成AccessToken
     *
     * @param accessToken accessToken
     * @return AccessToken
     * @throws AuthzException e
     */
    public static AccessToken parseAccessToken(String accessToken) throws TokenException {
        Claims claims = parseToken(accessToken);
        if (claims == null || claims.get(ID, String.class) == null) {
            throw new TokenException();
        }
        return new AccessToken(claims.get(ID, String.class), accessToken, claims.getId(), null,
                               claims.getExpiration().getTime(),
                               GrantType.grantType(claims.get(GRANT_TYPE, String.class)),
                               claims.get(CLIENT_ID, String.class),
                               claims.get(SCOPE, String.class),
                               claims.get(USER_ID), claims.get(DEVICE_TYPE, String.class),
                               claims.get(DEVICE_ID, String.class));
    }

    /**
     * 根据tokenVal解析生成AccessToken
     *
     * @param refreshToken refreshToken
     * @return AccessToken
     * @throws AuthzException e
     */
    public static RefreshToken parseRefreshToken(String refreshToken) throws TokenException {
        Claims claims = parseToken(refreshToken);
        if (claims == null) {
            throw new TokenException();
        }
        return new RefreshToken(refreshToken, claims.getId(),
                                null,
                                claims.getExpiration().getTime(),
                                claims.get(USER_ID),
                                claims.get(CLIENT_ID, String.class));
    }

    public static IssueToken createIssueToken(TokenPair tokenPair) {
        GrantType grantType = tokenPair.getAccessToken().getGrantType();
        IssueToken token = new IssueToken().setAccessToken(tokenPair.getAccessToken().getToken())
                .setScope(tokenPair.getAccessToken().getScope())
                .setExpiresIn(tokenPair.getAccessToken().getExpiresIn());
        if (!GrantType.CLIENT_CREDENTIALS.equals(grantType)) {
            return token.setRefreshToken(tokenPair.getRefreshToken().getToken());
        } else {
            return token;
        }
    }
}
