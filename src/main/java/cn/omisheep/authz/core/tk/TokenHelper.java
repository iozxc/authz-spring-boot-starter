package cn.omisheep.authz.core.tk;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.oauth.AuthorizationInfo;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.UUIDBits;
import cn.omisheep.web.utils.HttpUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static cn.omisheep.authz.core.config.Constants.*;
import static io.jsonwebtoken.CompressionCodecs.DEFLATE;
import static io.jsonwebtoken.CompressionCodecs.GZIP;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public class TokenHelper {

    private static final Long      accessTime; // 存活时间,单位 ms
    private static final Long      refreshTime; // 存活时间,单位 ms
    private static final String    issuer;
    private static final int       expire;
    private static final String    cookieName;
    private static final SecretKey secretKey;

    private static final SignatureAlgorithm               alg;
    private static final CompressionCodec                 codec;
    private static final AuthzProperties.TokenConfig.Mode mode;
    private static final int                              tokenIdBits;
    private static final String                           prefix;
    private static final String                           defaultScope;

    private TokenHelper() {
    }

    static {
        AuthzProperties             properties = AUtils.getBean(AuthzProperties.class);
        AuthzProperties.TokenConfig token      = properties.getToken();
        defaultScope = token.getOauth().getDefaultScope();
        String             key       = token.getKey();
        SignatureAlgorithm algorithm = token.getAlgorithm();
        tokenIdBits = token.getTokenIdBits();
        if (key == null || key.equals("") || algorithm == null || algorithm == SignatureAlgorithm.NONE) {
            alg       = SignatureAlgorithm.NONE;
            secretKey = null;
        } else {
            StringBuilder stringBuilder = new StringBuilder(key);
            if (stringBuilder.length() * 8 < algorithm.getMinKeyLength()) {
                while (stringBuilder.length() * 8 < algorithm.getMinKeyLength()) {
                    stringBuilder.append(".");
                }
            }
            secretKey = Keys.hmacShaKeyFor(stringBuilder.toString().getBytes(StandardCharsets.UTF_8));
            alg       = algorithm;
        }
        AuthzProperties.TokenConfig.Compress compress = token.getCompress();
        if (compress == AuthzProperties.TokenConfig.Compress.DEFLATE) {
            codec = DEFLATE;
        } else if (compress == AuthzProperties.TokenConfig.Compress.GZIP) {
            codec = GZIP;
        } else {
            codec = null;
        }

        AuthzProperties.TokenConfig.Mode m = token.getMode();
        if (m == null) mode = AuthzProperties.TokenConfig.Mode.STANDARD;
        else mode = m;
        String prefix1;
        if (mode == AuthzProperties.TokenConfig.Mode.BRIEF) {
            JwsHeader jwsHeader = Jwts.jwsHeader();
            if (alg != SignatureAlgorithm.NONE) jwsHeader.setAlgorithm(alg.getValue());
            if (codec != null) jwsHeader.setCompressionAlgorithm(codec.getAlgorithmName());
            try {
                byte[] bytes = new ObjectMapper().writeValueAsBytes(jwsHeader);
                prefix1 = Encoders.BASE64URL.encode(bytes) + ".";
            } catch (JsonProcessingException e) {
                LogUtils.error(e);
                prefix1 = "";
            }

        } else {
            prefix1 = "";
        }

        prefix      = prefix1;
        issuer      = token.getIssuer();
        expire      = (int) (TimeUtils.parseTimeValue(token.getRefreshTime()) / 1000);
        cookieName  = properties.getToken().getCookieName();
        accessTime  = TimeUtils.parseTimeValue(token.getAccessTime());
        refreshTime = TimeUtils.parseTimeValue(token.getRefreshTime());
    }

    /**
     * 生成claims
     *
     * @param userId     用户id
     * @param deviceId   设备Id
     * @param deviceType 设备系统类型
     * @param tokenType  token类型 accessToken和refreshToken
     * @return claims
     */
    private static Claims generateClaims(Object userId, String deviceType, String deviceId, String clientId,
                                         String scope, Token.Type tokenType) {
        Claims claims = Jwts.claims();
        claims.put(USER_ID, userId);
        claims.put(DEVICE_ID, deviceId);
        claims.put(DEVICE_TYPE, deviceType);
        claims.put(TOKEN_TYPE, tokenType.names.get(0));
        if (clientId != null) { // oauth
            if (scope == null) claims.put(SCOPE, defaultScope);
            else claims.put(SCOPE, scope);
            claims.put(CLIENT_ID, clientId);
        }
        return claims;
    }

    /**
     * 创建一个 TokenPair（ accessToken，refreshToken ）
     *
     * @param info AuthorizationInfo
     * @return TokenPair
     */
    public static TokenPair createTokenPair(AuthorizationInfo info) {
        return createTokenPair(info.getUserId(), info.getDeviceType(), info.getDeviceId(), info.getClientId(),
                               info.getScope());
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
        return createTokenPair(userId, deviceType, deviceId, null, null);
    }

    /**
     * 创建一个 TokenPair（ accessToken，refreshToken ）
     *
     * @param userId     用户id
     * @param deviceId   设备Id
     * @param deviceType 设备系统类型
     * @return TokenPair
     */
    public static TokenPair createTokenPair(Object userId, String deviceType, String deviceId, String clientId,
                                            String scope) {
        LocalDateTime now     = LocalDateTime.now();
        Date          fromNow = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date toAccessExpiredTime = // accessToken失效时间
                Date.from(now.plus(accessTime, ChronoUnit.MILLIS).atZone(
                        ZoneId.systemDefault()).toInstant());
        Date toRefreshExpiredTime = // refreshToken失效时间
                Date.from(now.plus(refreshTime, ChronoUnit.MILLIS).atZone(
                        ZoneId.systemDefault()).toInstant());

        Token accessToken = createToken(userId, deviceType, deviceId, Token.Type.ACCESS, fromNow,
                                        toAccessExpiredTime, clientId, scope);
        Token refreshToken = createToken(userId, deviceType, deviceId, Token.Type.REFRESH, fromNow,
                                         toRefreshExpiredTime, clientId, scope);

        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * 创建Token
     *
     * @param userId     用户id
     * @param deviceId   设备Id
     * @param deviceType 设备系统类型
     * @param from       从多久开始
     * @param to         到多久结束
     * @param clientId   客户端id
     * @param scope      授权范围
     * @return Token
     */
    private static Token createToken(Object userId, String deviceType, String deviceId, Token.Type type, Date from,
                                     Date to, String clientId, String scope) {
        Claims claims = generateClaims(userId, deviceType, deviceId, clientId, scope, type);

        String tokenId = UUIDBits.getUUIDBits(tokenIdBits);

        JwtBuilder jwtBuilder = Jwts.builder().setClaims(claims) // 设置 claims
                .setId(tokenId).setIssuedAt(from) // 发行时间
                .setExpiration(to);
        if (secretKey != null) {
            jwtBuilder.signWith(secretKey, alg);
        }
        if (issuer != null) {
            jwtBuilder.setIssuer(issuer); // 发行用户
        }
        if (codec != null) {
            jwtBuilder.compressWith(codec);
        }
        String tokenVal = jwtBuilder.compact();
        if (mode == AuthzProperties.TokenConfig.Mode.BRIEF) {
            tokenVal = tokenVal.substring(tokenVal.indexOf(".") + 1);
        }
        return new Token(tokenVal, userId, tokenId, from, to, deviceType, deviceId, clientId, scope, type);
    }

    /**
     * 利用RefreshTokenVal刷新，获得新到accessToken
     *
     * @param refreshTokenVal refreshTokenVal
     * @return TokenPair
     */
    public static TokenPair refreshToken(String refreshTokenVal) {
        return refreshToken(parseToken(refreshTokenVal));
    }

    /**
     * 利用token刷新，获得新到accessToken
     *
     * @param refreshToken refreshToken
     * @return TokenPair
     */
    public static TokenPair refreshToken(Token refreshToken) {
        if (refreshToken == null || !refreshToken.getType().equals(Token.Type.REFRESH)) {
            return null;
        }
        Token accessToken = createToken(refreshToken.getUserId(), refreshToken.getDeviceType(),
                                        refreshToken.getDeviceId(), Token.Type.ACCESS, TimeUtils.now(), Date.from(
                        LocalDateTime.now().plus(accessTime, ChronoUnit.MILLIS).atZone(
                                ZoneId.systemDefault()).toInstant()), refreshToken.getClientId(),
                                        refreshToken.getScope());
        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * 根据Token生成一个Cookie
     *
     * @param token 目标Token
     * @return Cookie
     */
    public static Cookie generateCookie(Token token) {
        if (token == null) return null;
        Cookie cookie = new Cookie(cookieName, token.getTokenVal());
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

    /**
     * 根据tokenVal解析生成Token
     *
     * @param tokenVal tokenVal
     * @return Token
     */
    public static Token parseToken(String tokenVal) {
        if (tokenVal == null || tokenVal.equals("")) return null;
        String tv = null;
        if (mode == AuthzProperties.TokenConfig.Mode.BRIEF) {
            tv       = tokenVal;
            tokenVal = prefix + tokenVal;
        }
        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(tokenVal).getBody();
        return new Token(tv != null ? tv : tokenVal, claims.get(USER_ID), claims.getId(),
                         claims.getIssuedAt(), claims.getExpiration(),
                         claims.get(DEVICE_TYPE, String.class),
                         claims.get(DEVICE_ID, String.class), claims.get(CLIENT_ID, String.class),
                         claims.get(SCOPE, String.class),
                         Token.Type.fromValue((String) claims.get(TOKEN_TYPE)));
    }

}
