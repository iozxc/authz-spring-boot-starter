package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.HttpUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.Cookie;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Order(0)
@SuppressWarnings("all")
public class CookieAndRequestSlot implements Slot {

    private final UserDevicesDict userDevicesDict;
    private final boolean isEnableRedis;
    private final String cookieName;

    public CookieAndRequestSlot(UserDevicesDict userDevicesDict, PermLibrary permLibrary, AuthzProperties properties) {
        this.userDevicesDict = userDevicesDict;
        this.isEnableRedis = properties.getCache().isEnableRedis();
        this.cookieName = properties.getCookieName();
    }

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) throws Exception {
        Cookie cookie = HttpUtils.readSingleCookieInRequestByName(cookieName);
        if (httpMeta.setHasTokenCookie(cookie != null)) {
            try {
                Token token = TokenHelper.parseToken(cookie.getValue());
                httpMeta.setToken(token);
                // 每次访问将最后一次访问时间和ip存入缓存中
                Async.run(userDevicesDict::request);
            } catch (Exception e) {
                // 惰性删除策略，如果此用户存在，但是过期，则删除
                httpMeta.setTokenException(HttpMeta.TokenException.valueOf(e.getClass().getSimpleName()));
                if (!isEnableRedis && e instanceof ExpiredJwtException) {
                    Claims claims = ((ExpiredJwtException) e).getClaims();
                    userDevicesDict.removeDeviceByUserIdAndAccessTokenId(claims.get("userId"), claims.getId());
                }
            }
        }
        return true;
    }

}
