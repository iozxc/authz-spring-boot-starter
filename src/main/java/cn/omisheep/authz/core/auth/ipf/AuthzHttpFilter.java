package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.BannedType;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.RequestExceptionStatus;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.HttpUtils;
import cn.omisheep.commons.web.BufferedServletRequestWrapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import orestes.bloomfilter.CountingBloomFilter;
import org.springframework.boot.logging.LogLevel;
import org.springframework.http.HttpStatus;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class AuthzHttpFilter extends OncePerRequestFilter {

    private final AntPathMatcher antPathMatcher = new AntPathMatcher("/");
    private final AuthzProperties properties;
    private final Httpd httpd;
    private final UserDevicesDict userDevicesDict;

    public AuthzHttpFilter(Httpd httpd, UserDevicesDict userDevicesDict, AuthzProperties properties) {
        this.httpd = httpd;
        this.userDevicesDict = userDevicesDict;
        this.properties = properties;
    }

    @Override
    public void doFilterInternal(HttpServletRequest rrequest,
                                 HttpServletResponse response,
                                 FilterChain filterChain) throws ServletException, IOException {

        HttpServletRequest request = new BufferedServletRequestWrapper(rrequest);
        String ip = getIp(request); // ip
        String uri = request.getRequestURI(); // uri
        String method = request.getMethod();

        //  记录访问次数，同时保存所访问的api，不能直接用uri。因为路径可能也为参数
        String api = execLimit(ip, uri, method); // api

        if (api == null) {
            LogUtils.exportLogsFromRequest();
            return;
        }

        HttpMeta httpMeta = new HttpMeta(
                request,
                ip, uri, api, method, new Date());

        request.setAttribute(Constants.HTTP_META, httpMeta);

        // 获取Cookie
        Cookie cookie = HttpUtils.readSingleCookieInRequestByName(properties.getCookieName());
        httpMeta.setHasTokenCookie(cookie != null);

        if (httpMeta.isHasTokenCookie()) {
            try {
                Token token = TokenHelper.parseToken(cookie.getValue());
                httpMeta.setToken(token);
                // 每次访问将最后一次访问时间和ip存入缓存中
                Async.run(() -> userDevicesDict.request());
            } catch (Exception e) {
                // 惰性删除策略，如果此用户存在，但是过期，则删除
                httpMeta.setTokenException(HttpMeta.TokenException.valueOf(e.getClass().getSimpleName()));
                if (!properties.getCache().isEnabledRedis() && e instanceof ExpiredJwtException) {
                    Claims claims = ((ExpiredJwtException) e).getClaims();
                    userDevicesDict.removeDeviceByUserIdAndAccessTokenId(claims.get("userId"), claims.getId());
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private String execLimit(String ip, String uri, String method) throws IOException {
        HashSet<RequestMeta> ipBlacklist = httpd.getIpBlacklist();
        CountingBloomFilter<String> ipBlacklistBloomFilter = httpd.getIpBlacklistBloomFilter();

        long now = new Date().getTime();

        // 全局ip黑名单过滤
        if (ipBlacklistBloomFilter.contains(ip)) { // 使用布隆过滤器过滤。若存在，则去黑名单里搜索
            RequestMeta orElse = ipBlacklist.stream() // 黑名单内搜索
                    .filter(_ipMeta -> _ipMeta.getIp().equals(ip)).findFirst().orElse(null);
            if (orElse != null && orElse.isBan()) { // 若存在且确实是被禁止了。则
                if (!orElse.enableRelive(now)) {
                    LogUtils.pushLogToRequest("「请求频繁ip封锁(拒绝)」 \t距上次访问: [{}] , method: [{}] , ip : [{}] , uri: [{}]  ", orElse.sinceLastTime(), method, ip, uri);
                    HttpUtils.returnResponse(HttpStatus.FORBIDDEN, RequestExceptionStatus.REQUEST_REPEAT);
                    return null;
                } else {
                    LogUtils.pushLogToRequest("「解除ip封禁(解封)」");
                    ipBlacklistBloomFilter.remove(ip);
                    ipBlacklist.remove(orElse);
                    orElse.relive();
                }
            } // 假阳性，不做任何操作
        }

        // 局部api黑名单过滤
        for (Map.Entry<String, Httpd.RequestPool> entry : httpd.getRequestPools().get(method).entrySet()) {
            if (antPathMatcher.match(entry.getKey(), uri)) {
                LimitMeta limitMeta = null;

                try {
                    limitMeta = httpd.getRateLimitMetadata().get(method).get(entry.getKey());
                } catch (NullPointerException e) {
                    LogUtils.pushLogToRequest("「普通访问」 \tmethod: [{}] , ip : [{}] , uri: [{}]   ", method, ip, uri);
                    return entry.getKey();
                }

                if (limitMeta == null) {
                    LogUtils.pushLogToRequest("「普通访问」 \tmethod: [{}] , ip : [{}] , uri: [{}]   ", method, ip, uri);
                    return entry.getKey();
                }

                RequestMeta ipMeta = entry.getValue().get(ip);
                if (ipMeta == null) {
                    entry.getValue().put(ip, new RequestMeta(now, ip));
                    LogUtils.pushLogToRequest("「普通访问(首次)」 \tmethod: [{}] , ip : [{}] , uri: [{}]  ", method, ip, uri);
                } else {
                    if (ipMeta.isBan()) {
                        if (!ipMeta.enableRelive(now)) {
                            LogUtils.pushLogToRequest(LogLevel.WARN, "「请求频繁(拒绝)」 \t距上次访问: [{}] , method: [{}] , ip : [{}] , uri: [{}]  ", ipMeta.sinceLastTime(), method, ip, uri);
                            HttpUtils.returnResponse(HttpStatus.FORBIDDEN, RequestExceptionStatus.REQUEST_REPEAT);
                            ipMeta.setLastRequestTime(now);
                            return null;
                        } else {
                            LogUtils.pushLogToRequest("「解除封禁(解封)」  \tmethod: [{}] , ip : [{}] , uri: [{}]  ", method, ip, uri);
                            ipMeta.relive();
                            for (Httpd.RequestPool ipPool : oIpPools(limitMeta)) {
                                if (ipPool.containsKey(ip)) {
                                    ipPool.get(ip).relive();
                                }
                            }
                        }
                    }
                    if (ipMeta.request(now, limitMeta.getMaxRequests(), limitMeta.getWindow(), limitMeta.getMinInterval())) {
                        LogUtils.pushLogToRequest("「普通访问(正常)」\t距上次访问: [{}] , method: [{}] , ip : [{}] , uri: [{}]  ", ipMeta.sinceLastTime(), method, ip, uri);
                    } else {
                        ipMeta.forbidden(limitMeta.getPunishmentTime());

                        for (Httpd.RequestPool ipPool : oIpPools(limitMeta)) {
                            long time = ipMeta.getLastRequestTime().getTime();
                            if (!ipPool.contains(ip)) {
                                ipPool.put(ip, new RequestMeta(now, ip).forbidden(limitMeta.getPunishmentTime()));
                            } else ipPool.get(ip).forbidden(limitMeta.getPunishmentTime());
                        }

                        LogUtils.pushLogToRequest(LogLevel.WARN, "「请求频繁(封禁)」 \t距上次访问: [{}] , method: [{}] , ip : [{}] , uri: [{}]  ", ipMeta.sinceLastTime(), method, ip, uri);
                        HttpUtils.returnResponse(HttpStatus.FORBIDDEN, RequestExceptionStatus.REQUEST_REPEAT);
                        if (BannedType.IP.equals(limitMeta.getBannedType())) {
                            ipBlacklist.add(ipMeta); // 若是封锁ip，则添加到ipBlacklist中，在第一层ip过滤时则会将其拦下
                            ipBlacklistBloomFilter.add(ip);
                        }
                        return null;
                    }
                }

                return entry.getKey();
            }
        }

        LogUtils.pushLogToRequest("「普通访问(uri不存在)」 \tmethod: [{}] , ip : [{}] , uri: [{}]   ", method, ip, uri);
        HttpUtils.returnResponse(HttpStatus.NOT_FOUND);
        return null;
    }

    public List<Httpd.RequestPool> oIpPools(LimitMeta limitMeta) {
        List<Httpd.RequestPool> requestPools = httpd.getAssociatedIpPoolsCache().get(limitMeta);
        if (requestPools != null) return requestPools;

        List<LimitMeta.AssociatedPattern> associatedPatterns = limitMeta.getAssociatedPatterns();
        List<Httpd.RequestPool> oIpPools = new ArrayList<>();
        if (associatedPatterns != null) {
            associatedPatterns.stream().forEach(associatedPattern -> {
                associatedPattern.getMethods().forEach(meth -> {
                    ConcurrentHashMap<String, Httpd.RequestPool> map = httpd.getRequestPools()
                            .get(meth);
                    if (map != null) {
                        map.keySet()
                                .stream().filter(path -> antPathMatcher.match(associatedPattern.getPattern(), path))
                                .forEach(path -> oIpPools.add(map.get(path)));
                    }
                });
            });
        }

        httpd.getAssociatedIpPoolsCache().put(limitMeta, oIpPools);
        return oIpPools;
    }


    private static final String UNKNOWN = "unknown";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String PROXY_CLIENT_IP = "Proxy-Client-IP";
    private static final String WL_PROXY_CLIENT_IP = "WL-Proxy-Client-IP";
    private static final String HTTP_CLIENT_IP = "HTTP_CLIENT_IP";
    private static final String HTTP_X_FORWARDED_FOR = "HTTP_X_FORWARDED_FOR";
    private static final String X_REAL_IP = "X-Real-IP";

    private String getIp(HttpServletRequest request) {
        String ip = request.getHeader(X_FORWARDED_FOR);
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(PROXY_CLIENT_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(WL_PROXY_CLIENT_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(HTTP_CLIENT_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(HTTP_X_FORWARDED_FOR);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(X_REAL_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getRemoteAddr();
            }
        } else if (ip.length() > 15) {
            String[] ips = ip.split(Constants.COMMA);
            for (int index = 0; index < ips.length; index++) {
                String strIp = (String) ips[index];
                if (!(UNKNOWN.equalsIgnoreCase(strIp))) {
                    ip = strIp;
                    break;
                }
            }
        }
        return ip.equals("0:0:0:0:0:0:0:1") ? "127.0.0.1" : ip;
    }

}

