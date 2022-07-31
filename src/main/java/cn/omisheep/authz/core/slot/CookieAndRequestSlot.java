package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.commons.util.Async;
import cn.omisheep.web.utils.HttpUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.Cookie;
import java.util.Locale;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.UserStatus.ACCESS_TOKEN_OVERDUE;
import static cn.omisheep.authz.core.config.Constants.REFRESH_TOKEN_ID;
import static cn.omisheep.authz.core.config.Constants.USER_ID;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Order(2)
@SuppressWarnings("all")
public class CookieAndRequestSlot implements Slot {

    private final UserDevicesDict userDevicesDict;
    private final boolean         isEnableRedis;
    private final String          cookieName;
    private final String          headerName;
    private final String          headerPrefix;

    public CookieAndRequestSlot(UserDevicesDict userDevicesDict, PermLibrary permLibrary, AuthzProperties properties) {
        this.userDevicesDict = userDevicesDict;
        this.isEnableRedis   = properties.getCache().isEnableRedis();
        this.cookieName      = properties.getToken().getCookieName();
        this.headerName      = properties.getToken().getHeaderName().toLowerCase(Locale.ROOT);
        this.headerPrefix    = properties.getToken().getHeaderPrefix();
    }

    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        Cookie cookie     = HttpUtils.readSingleCookieInRequestByName(cookieName);
        String tokenValue = null;

        String s = HttpUtils.getCurrentRequestHeaders().get(headerName);
        if (s != null && s.startsWith(headerPrefix)) {
            tokenValue = s.substring(headerPrefix.length());
        }

        if (tokenValue == null && cookie != null) {
            tokenValue = cookie.getValue();
        }

        if (tokenValue != null) {
            try {
                AccessToken accessToken = TokenHelper.parseAccessToken(tokenValue);
                httpMeta.setToken(accessToken);
                // 每次访问将最后一次访问时间和ip存入缓存中
                Async.run(userDevicesDict::request);
                httpMeta.setHasToken(true);
            } catch (Exception e) {
                if (e instanceof JwtException) {
                    httpMeta.setHasToken(false);
                    try {
                        TokenHelper.clearCookie();
                        if (e instanceof ExpiredJwtException) {
                            Claims claims = ((ExpiredJwtException) e).getClaims();
                            userDevicesDict.removeDeviceByTokenId(claims.get(USER_ID),
                                                                  claims.get(REFRESH_TOKEN_ID, String.class));
                        }
                    } catch (Exception ee) {
                        // skip
                    } finally {
                        httpMeta.setUserStatus(ACCESS_TOKEN_OVERDUE);
                    }
                }
            }
        } else {
            httpMeta.setHasToken(false);
        }

    }

}
