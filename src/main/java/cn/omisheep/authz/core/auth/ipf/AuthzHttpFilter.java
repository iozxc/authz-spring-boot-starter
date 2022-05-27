package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.BannedType;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.msg.RequestMessage;
import cn.omisheep.authz.core.util.ExceptionUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.web.utils.BufferedServletRequestWrapper;
import cn.omisheep.web.utils.HttpUtils;
import lombok.extern.slf4j.Slf4j;
import orestes.bloomfilter.CountingBloomFilter;
import org.springframework.boot.logging.LogLevel;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static cn.omisheep.authz.core.Constants.HTTP_META;
import static cn.omisheep.authz.core.auth.ipf.Httpd.antPathMatcher;
import static cn.omisheep.authz.core.util.Utils.isIgnoreSuffix;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class AuthzHttpFilter extends OncePerRequestFilter {

    private final Httpd   httpd;
    private final boolean isDashboard;
    private final String  mappings;

    public AuthzHttpFilter(Httpd httpd, boolean isDashboard, String mappings) {
        this.httpd       = httpd;
        this.isDashboard = isDashboard;
        String val = mappings.substring(0, mappings.indexOf("/*"));
        if (!mappings.startsWith("/")) {
            this.mappings = "/" + val;
        } else {
            this.mappings = val;
        }
    }

    @Override
    public void doFilterInternal(HttpServletRequest rrequest,
                                 HttpServletResponse response,
                                 FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest request = new BufferedServletRequestWrapper(rrequest);

        String ip          = getIp(request);
        String uri         = request.getRequestURI();
        String method      = request.getMethod();
        long   now         = new Date().getTime();
        String servletPath = request.getServletPath();

        HttpUtils.request.set(request);

        if (isIgnoreSuffix(uri, httpd.getIgnoreSuffix()) || (isDashboard && uri.startsWith(mappings))) {
            HttpMeta httpMeta = new HttpMeta(
                    request,
                    ip, uri, servletPath, method, new Date()).error(ExceptionUtils.pop(request));
            httpMeta.setIgnore(true);
            request.setAttribute(HTTP_META, httpMeta);
            httpMeta.setServletPath(servletPath);
            filterChain.doFilter(request, response);
            return;
        }

        String api = null;
        try {
            api = execLimit(now, ip, servletPath, method);
        } catch (Exception e) {
            // skip
            ExceptionUtils.error(ExceptionStatus.UNKNOWN);
        }

        if (api == null) api = servletPath;
        HttpMeta httpMeta = new HttpMeta(
                request,
                ip, uri, api, method, new Date()).error(ExceptionUtils.pop(request));

        httpMeta.setServletPath(servletPath);
        request.setAttribute(HTTP_META, httpMeta);
        Async.run(() -> RedisUtils.publish(RequestMessage.CHANNEL, new RequestMessage(method, httpMeta.getApi(), ip, now, null)));

        filterChain.doFilter(request, response);
    }

    private String execLimit(long now, String ip, String servletPath, String method) throws IOException {
        HashSet<RequestMeta>        ipBlacklist            = httpd.getIpBlacklist();
        CountingBloomFilter<String> ipBlacklistBloomFilter = httpd.getIpBlacklistBloomFilter();

        // 全局ip黑名单过滤
        if (ipBlacklistBloomFilter.contains(ip)) { // 使用布隆过滤器过滤。若存在，则去黑名单里搜索
            RequestMeta orElse = ipBlacklist.stream() // 黑名单内搜索
                    .filter(_ipMeta -> _ipMeta.getIp().equals(ip)).findFirst().orElse(null);
            if (orElse != null && orElse.isBan()) { // 若存在且确实是被禁止了。则
                if (!orElse.enableRelive(now)) {
                    LogUtils.pushLogToRequest("「请求频繁ip封锁(拒绝)」 \t距上次访问: [{}] , method: [{}] , ip : [{}] , servletPath: [{}]  ", orElse.sinceLastTime(), method, ip, servletPath);
                    ExceptionUtils.error(ExceptionStatus.REQUEST_REPEAT);
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
        ConcurrentHashMap<String, Httpd.RequestPool> map = httpd.getRequestPools().get(method);
        if (map == null) {
            LogUtils.pushLogToRequest("「普通访问(uri不存在)」 \tmethod: [{}] , ip : [{}] , servletPath: [{}]   ", method, ip, servletPath);
            ExceptionUtils.error(ExceptionStatus.MISMATCHED_URL);
            return null;
        }

        for (Map.Entry<String, Httpd.RequestPool> entry : map.entrySet()) {
            if (antPathMatcher.match(entry.getKey(), servletPath)) {
                LimitMeta limitMeta = null;

                try {
                    limitMeta = httpd.getRateLimitMetadata().get(method).get(entry.getKey());
                } catch (NullPointerException e) {
                    LogUtils.pushLogToRequest("「普通访问」 \tmethod: [{}] , ip : [{}] , servletPath: [{}]   ", method, ip, servletPath);
                    return entry.getKey();
                }

                if (limitMeta == null) {
                    LogUtils.pushLogToRequest("「普通访问」 \tmethod: [{}] , ip : [{}] , servletPath: [{}]   ", method, ip, servletPath);
                    return entry.getKey();
                }

                RequestMeta ipMeta = entry.getValue().get(ip);
                if (ipMeta == null) {
                    entry.getValue().put(ip, new RequestMeta(now, ip));
                    LogUtils.pushLogToRequest("「普通访问(首次)」 \tmethod: [{}] , ip : [{}] , servletPath: [{}]  ", method, ip, servletPath);
                } else {
                    if (ipMeta.isBan()) {
                        if (!ipMeta.enableRelive(now)) {
                            LogUtils.pushLogToRequest(LogLevel.WARN, "「请求频繁(拒绝)」 \t距上次访问: [{}] , method: [{}] , ip : [{}] , servletPath: [{}]  ", ipMeta.sinceLastTime(), method, ip, servletPath);
                            ExceptionUtils.error(ExceptionStatus.REQUEST_REPEAT);
                            ipMeta.setLastRequestTime(now);
                            return null;
                        } else {
                            LogUtils.pushLogToRequest("「解除封禁(解封)」  \tmethod: [{}] , ip : [{}] , servletPath: [{}]  ", method, ip, servletPath);
                            httpd.relive(ipMeta, limitMeta);
                        }
                    }
                    if (ipMeta.request(now, limitMeta.getMaxRequests(), limitMeta.getWindow(), limitMeta.getMinInterval())) {
                        LogUtils.pushLogToRequest("「普通访问(正常)」\t距上次访问: [{}] , method: [{}] , ip : [{}] , servletPath: [{}]  ", ipMeta.sinceLastTime(), method, ip, servletPath);
                    } else {
                        httpd.forbid(now, ipMeta, limitMeta);
                        LogUtils.pushLogToRequest(LogLevel.WARN, "「请求频繁(封禁)」 \t距上次访问: [{}] , method: [{}] , ip : [{}] , servletPath: [{}]  ", ipMeta.sinceLastTime(), method, ip, servletPath);
                        ExceptionUtils.error(ExceptionStatus.REQUEST_REPEAT);
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

        LogUtils.pushLogToRequest("「普通访问(uri不存在)」 \tmethod: [{}] , ip : [{}] , servletPath: [{}]   ", method, ip, servletPath);
        ExceptionUtils.error(ExceptionStatus.MISMATCHED_URL);
        return null;
    }

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
            for (String strIp : ips) {
                if (!(UNKNOWN.equalsIgnoreCase(strIp))) {
                    ip = strIp;
                    break;
                }
            }
        }
        return ip.equals("0:0:0:0:0:0:0:1") ? "127.0.0.1" : ip;
    }

    private static final String UNKNOWN              = "unknown";
    private static final String X_FORWARDED_FOR      = "x-forwarded-for";
    private static final String PROXY_CLIENT_IP      = "Proxy-Client-IP";
    private static final String WL_PROXY_CLIENT_IP   = "WL-Proxy-Client-IP";
    private static final String HTTP_CLIENT_IP       = "HTTP_CLIENT_IP";
    private static final String HTTP_X_FORWARDED_FOR = "HTTP_X_FORWARDED_FOR";
    private static final String X_REAL_IP            = "X-Real-IP";

}

