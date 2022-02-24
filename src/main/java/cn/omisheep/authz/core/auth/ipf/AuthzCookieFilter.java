package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.util.ExceptionUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.HttpUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuthzCookieFilter extends OncePerRequestFilter {

    private final UserDevicesDict userDevicesDict;
    private final boolean isEnableRedis;
    private final String cookieName;

    public AuthzCookieFilter(UserDevicesDict userDevicesDict, AuthzProperties properties) {
        this.userDevicesDict = userDevicesDict;
        this.isEnableRedis = properties.getCache().isEnableRedis();
        this.cookieName = properties.getCookieName();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!ExceptionUtils.isSafe(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpMeta httpMeta = (HttpMeta) request.getAttribute(Constants.HTTP_META);
        // 获取Cookie
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
        filterChain.doFilter(request, response);
    }
}
