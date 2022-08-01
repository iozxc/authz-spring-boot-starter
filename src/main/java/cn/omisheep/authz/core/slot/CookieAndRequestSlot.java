package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.annotation.AuthRequestToken;
import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.ExceptionStatus;
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
import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.UserStatus.REQUIRE_LOGIN;
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
        String tokenValue = null;

        AuthRequestToken authRequestToken = handler.getMethodAnnotation(AuthRequestToken.class);

        if (authRequestToken != null) {
            if (!authRequestToken.header().equals("")) {
                tokenValue = HttpUtils.getCurrentRequestHeaders().get(
                        authRequestToken.header().toLowerCase(Locale.ROOT));
            }

            if (tokenValue == null && !authRequestToken.cookie().equals("")) {
                Cookie cookie = HttpUtils.readSingleCookieInRequestByName(authRequestToken.cookie());
                tokenValue = cookie.getValue();
            }

            if (tokenValue == null && !authRequestToken.param().equals("")) {
                tokenValue = httpMeta.getRequest().getParameter(authRequestToken.param());
            }
        }

        if (tokenValue == null) {
            String s = HttpUtils.getCurrentRequestHeaders().get(headerName);
            if (s != null && s.startsWith(headerPrefix)) {
                tokenValue = s.substring(headerPrefix.length());
            }
        }

        Cookie cookie = HttpUtils.readSingleCookieInRequestByName(cookieName);
        if (tokenValue == null && cookie != null) {
            tokenValue = cookie.getValue();
        }

        if (tokenValue != null) {
            try {
                AccessToken accessToken = TokenHelper.parseAccessToken(tokenValue);
                httpMeta.setToken(accessToken);
                Async.run(userDevicesDict::request);
            } catch (Exception e) {
                httpMeta.setHasToken(false);
                TokenHelper.clearCookie();
                if (e instanceof JwtException) {
                    try {
                        if (e instanceof ExpiredJwtException) {
                            Claims claims = ((ExpiredJwtException) e).getClaims();
                            userDevicesDict.removeDeviceByTokenId(claims.get(USER_ID),
                                                                  claims.get(REFRESH_TOKEN_ID, String.class));
                            httpMeta.setUserStatus(ACCESS_TOKEN_OVERDUE);
                        }else {
                            httpMeta.setUserStatus(REQUIRE_LOGIN);
                        }
                    } catch (Exception ee) {
                        // skip
                    }
                } else if (e instanceof AuthzException) {
                    if (ExceptionStatus.TOKEN_EXCEPTION.equals(((AuthzException) e).getExceptionStatus())) {
                        httpMeta.setUserStatus(REQUIRE_LOGIN);
                        error.error(ExceptionStatus.TOKEN_EXCEPTION);
                        return;
                    }
                } else {
                    error.error(e);
                    return;
                }
            }
        } else {
            httpMeta.setHasToken(false);
        }

    }

}
