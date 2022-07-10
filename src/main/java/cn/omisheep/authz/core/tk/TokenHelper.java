package cn.omisheep.authz.core.tk;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.util.TimeUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public class TokenHelper {

    @Getter
    private static final Long               liveTime; // 存活时间,单位 ms
    private static final Long               refreshTime; // 存活时间,单位 ms
    private static final String             issuer;
    private static final int                expire;
    private static final String             cookieName;
    private static final byte[]             keyBytes;
    private static final SignatureAlgorithm alg;

    private static final String USER_ID     = "userId";
    private static final String DEVICE_ID   = "deviceId";
    private static final String DEVICE_TYPE = "deviceType";
    private static final String TOKEN_TYPE  = "type";

    private TokenHelper() {
    }

    static {
        AuthzProperties properties = AUtils.getBean(AuthzProperties.class);
        keyBytes    = TextCodec.BASE64.decode(properties.getToken().getKey());
        issuer      = properties.getToken().getIssuer();
        expire      = (int) (TimeUtils.parseTimeValue(properties.getToken().getRefreshTime()) / 1000);
        cookieName  = properties.getToken().getCookieName();
        alg         = SignatureAlgorithm.HS256;
        liveTime    = TimeUtils.parseTimeValue(properties.getToken().getLiveTime());
        refreshTime = TimeUtils.parseTimeValue(properties.getToken().getRefreshTime());
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
    private static Claims generateClaims(Object userId, String deviceType, String deviceId, Token.Type tokenType) {
        // 设置token里的数据
        Claims claims = Jwts.claims().setSubject(userId.toString());
        claims.put(USER_ID, userId);
        claims.put(DEVICE_ID, deviceId);
        claims.put(DEVICE_TYPE, deviceType);
        claims.put(TOKEN_TYPE, tokenType);
        return claims;
    }

    /**
     * 创建一个 TokenPair（accessToken和refreshToken）
     *
     * @param userId     用户id
     * @param deviceId   设备Id
     * @param deviceType 设备系统类型
     * @return TokenPair
     */
    public static TokenPair createTokenPair(Object userId, String deviceType, String deviceId) {
        Date fromNow = Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant());
        Date toAccessExpiredTime = // accessToken失效时间
                Date.from(LocalDateTime.now().plus(liveTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());
        Date toRefreshExpiredTime = // refreshToken失效时间
                Date.from(LocalDateTime.now().plus(refreshTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());

        Token refreshToken = createToken(userId, deviceType, deviceId, Token.Type.REFRESH, fromNow, toRefreshExpiredTime);
        Token accessToken  = createToken(userId, deviceType, deviceId, Token.Type.ACCESS, fromNow, toAccessExpiredTime);
        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * 创建Token，此方法中builder为静态成员，所以需要加锁，
     *
     * @param userId     用户id
     * @param deviceId   设备Id
     * @param deviceType 设备系统类型
     * @param type       token类型 accessToken和refreshToken
     * @param from       从多久开始
     * @param to         到多久结束
     * @return Token
     */
    public static Token createToken(Object userId, String deviceType, String deviceId, Token.Type type, Date from, Date to) {
        Claims claims = generateClaims(userId, deviceType, deviceId, type);

        String tokenId = UUID.randomUUID().toString();

        String tokenVal = Jwts.builder().signWith(alg, keyBytes)
                .setClaims(claims) // 设置 claims
                .setId(tokenId)
                .setIssuer(issuer) // 发行用户
                .setIssuedAt(from) // 发行时间
                .setExpiration(to)
                .compact();
        return new Token(tokenVal, userId, tokenId, from, to, deviceType, deviceId, type);
    }

    /**
     * 利用tokenVal刷新，获得新到accessToken
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
        Token accessToken = createToken(refreshToken.getUserId(),
                refreshToken.getDeviceType(), refreshToken.getDeviceId(), Token.Type.ACCESS,
                TimeUtils.now(),
                Date.from(LocalDateTime.now().plus(liveTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant())
        );
        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * 根据Token生成一个Cookie
     *
     * @param token 目标Token
     * @return Cookie
     */
    public static Cookie generateCookie(Token token) {
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
     * 根据tokenVal解析生成Token
     *
     * @param tokenVal tokenVal
     * @return Token
     */
    public static Token parseToken(String tokenVal) {
        if (tokenVal == null || tokenVal.equals("")) return null;
        Claims claims = Jwts.parser().setSigningKey(keyBytes).parseClaimsJws(tokenVal).getBody();
        return new Token(tokenVal,
                claims.get(USER_ID),
                claims.getId(),
                claims.getIssuedAt(),
                claims.getExpiration(),
                claims.get(DEVICE_TYPE, String.class),
                claims.get(DEVICE_ID, String.class),
                Token.Type.valueOf(claims.get(TOKEN_TYPE, String.class))
        );
    }
}
