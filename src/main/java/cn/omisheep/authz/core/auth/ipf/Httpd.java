package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.core.msg.AuthzModifiable;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.authz.core.msg.RequestMessage;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.server.PathContainer;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static cn.omisheep.authz.annotation.RateLimit.CheckType.IP;
import static cn.omisheep.authz.annotation.RateLimit.CheckType.USER_ID;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class Httpd implements AuthzModifiable {

    private static final HashMap<String, PathPattern> pathMatcherMap = new HashMap<>();

    private static final PathPatternParser pathPatternParser = new PathPatternParser();

    @Getter
    @Setter
    private String[] ignoreSuffix;

    /**
     * 用于保存请求限制的信息
     */
    @Getter
    private final RequestPools ipRequestPools = new RequestPools();

    /**
     * 用于保存请求限制的信息
     */
    @Getter
    private final RequestPools userIdRequestPools = new RequestPools();

    /**
     * api限制访问次数信息map
     */
    @Getter
    private final Map<String, Map<String, LimitMeta>> rateLimitMetadata = new HashMap<>();

    @JsonIgnore
    private final HashMap<LimitMeta, List<RequestPool>> associatedIpPoolsCache = new HashMap<>();

    public static class RequestPools extends HashMap<String, ConcurrentHashMap<String, RequestPool>> {
        private static final long serialVersionUID = -1838299980303412207L;
    }

    public static class RequestPool extends ConcurrentHashMap<String, RequestMeta> {
        private static final long serialVersionUID = -284927742264879191L;
    }

    public LimitMeta getLimitMetadata(String method, String api) {
        Map<String, LimitMeta> limitMetaMap = rateLimitMetadata.get(api);
        if (limitMetaMap == null) return null;
        return limitMetaMap.get(method);
    }

    public void setPathPattern(String pattern) {
        pathMatcherMap.put(pattern, pathPatternParser.parse(pattern));
    }

    public boolean match(String pattern, String path) {
        PathPattern pathPattern = pathMatcherMap.get(pattern);
        if (pathPattern == null) return false;
        return pathPattern.matches(PathContainer.parsePath(path));
    }

    public String getPattern(String path) {
        for (Map.Entry<String, PathPattern> entry : pathMatcherMap.entrySet()) {
            if (entry.getValue().matches(PathContainer.parsePath(path))) {
                return entry.getKey();
            }
        }
        return null;
    }

    public String getPattern(String method, String path) {
        for (Map.Entry<String, PathPattern> entry : pathMatcherMap.entrySet()) {
            if (entry.getValue().matches(PathContainer.parsePath(path))) {
                ConcurrentHashMap<String, RequestPool> map = ipRequestPools.get(entry.getKey());
                if (map == null || map.isEmpty()) return null;
                if (map.get(method) == null) return null;
                return entry.getKey();
            }
        }
        return null;
    }

    public void receive(RequestMessage requestMessage) {
        String    api       = requestMessage.getApi();
        String    method    = requestMessage.getMethod();
        String    ip        = requestMessage.getIp();
        long      now       = requestMessage.getNow();
        Object    userId    = requestMessage.getUserId();
        LimitMeta limitMeta = getLimitMetadata(method, api);
        if (limitMeta == null) return;
        try {
            RateLimit.CheckType checkType = limitMeta.getCheckType();
            if (checkType.equals(USER_ID) && userId == null) return;
            Httpd.RequestPool ipRequestPool     = ipRequestPools.get(api).get(method);
            Httpd.RequestPool userIdRequestPool = userIdRequestPools.get(api).get(method);
            RequestMeta       requestMeta       = checkType.equals(IP) ? ipRequestPool.get(ip) : userIdRequestPool.get(userId.toString());
            if (requestMeta == null) {
                if (checkType.equals(IP)) {
                    ipRequestPool.put(ip, new RequestMeta(now, ip, null));
                } else {
                    userIdRequestPool.put(userId.toString(), new RequestMeta(now, null, userId));
                }
            } else {
                if (!requestMeta.pushRequest(now, limitMeta)) {
                    forbid(now, requestMeta, limitMeta, method, api);
                }
            }
        } catch (Exception ignore) {
        }
    }

    public List<Httpd.RequestPool> associatedIpPools(LimitMeta limitMeta) {
        List<Httpd.RequestPool> rps = associatedIpPoolsCache.get(limitMeta);
        if (rps != null) return rps;

        List<LimitMeta.AssociatedPattern> associatedPatterns = limitMeta._getAssociatedPatterns();
        RateLimit.CheckType               checkType          = limitMeta.getCheckType();
        List<Httpd.RequestPool>           oIpPools           = new ArrayList<>();
        if (associatedPatterns != null) {
            associatedPatterns.forEach(associatedPattern -> associatedPattern.getMethods().forEach(meth -> {
                RequestPools requestPools = checkType.equals(IP) ? ipRequestPools : userIdRequestPools;
                requestPools.keySet().stream().filter(path -> match(associatedPattern.getPattern(), path)).forEach(path -> oIpPools.add(requestPools.get(path).get(meth)));
            }));
        }

        associatedIpPoolsCache.put(limitMeta, oIpPools);
        return oIpPools;
    }

    public void forbid(long now, RequestMeta requestMeta, LimitMeta limitMeta, String method, String api) {
        requestMeta.forbidden(method, api, limitMeta);
        String ip     = requestMeta.getIp();
        Object userId = requestMeta.getUserId();
        for (Httpd.RequestPool ipPool : associatedIpPools(limitMeta)) {
            if (!ipPool.containsKey(ip)) {
                ipPool.put(ip, new RequestMeta(now, ip, userId).forbidden(method, api, limitMeta));
            } else ipPool.get(ip).forbidden(method, api, limitMeta);
        }
    }

    public void relive(RequestMeta requestMeta, LimitMeta limitMeta, String method, String api) {
        String ip = requestMeta.getIp();
        requestMeta.relive(method, api, limitMeta);
        associatedIpPools(limitMeta).forEach(ipPool -> {
            if (ipPool.containsKey(ip)) ipPool.get(ip).relive(method, api, limitMeta);
        });
    }

    @Nullable
    public synchronized Object modify(@NonNull AuthzModifier authzModifier) {
        try {
            switch (authzModifier.getOperate()) {
                case ADD:
                case MODIFY:
                case UPDATE:
                    AuthzModifier.RateLimitInfo rateLimit = authzModifier.getRateLimit();
                    LimitMeta limitMeta = new LimitMeta(rateLimit.getWindow(), rateLimit.getMaxRequests(), rateLimit.getPunishmentTime().toArray(new String[0]), rateLimit.getMinInterval(), rateLimit.getAssociatedPatterns().toArray(new String[0]), rateLimit.getCheckType());
                    rateLimitMetadata.get(authzModifier.getApi()).put(authzModifier.getMethod(), limitMeta);
                    return limitMeta;
                case DEL:
                case DELETE:
                    return rateLimitMetadata.get(authzModifier.getApi()).remove(authzModifier.getMethod());
                case READ:
                case GET:
                    return rateLimitMetadata.get(authzModifier.getApi()).get(authzModifier.getMethod());
                default:
                    return Result.FAIL;
            }
        } catch (Exception e) {
            LogUtils.error("modify error", e);
            return Result.FAIL;
        }
    }

    public static void setRateLimitCallback(RateLimitCallback callback) {
        RequestMeta.setCallback(callback);
    }

}
