package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.msg.RequestMessage;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.http.server.PathContainer;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static cn.omisheep.authz.annotation.RateLimit.CheckType.IP;
import static cn.omisheep.authz.annotation.RateLimit.CheckType.USER_ID;
import static cn.omisheep.authz.core.util.MetaUtils.getPatterns;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class Httpd {

    private static final HashMap<String, PathPattern> pathMatcherMap = new HashMap<>();

    private static final PathPatternParser pathPatternParser = new PathPatternParser();

    @Getter
    @Setter
    private static String[] ignoreSuffix;

    /**
     * 用于保存请求限制的信息
     */
    private static final RequestPools _ipRequestPools = new RequestPools();

    /**
     * 用于保存请求限制的信息
     */
    private static final RequestPools _userIdRequestPools = new RequestPools();

    /**
     * api限制访问次数信息map
     */
    private static final Map<String, Map<String, LimitMeta>> _rateLimitMetadata = new HashMap<>();

    @Getter
    private static final Map<String, Map<String, LimitMeta>> rateLimitMetadata = Collections.unmodifiableMap(
            _rateLimitMetadata);

    @Getter
    private static final Map<String, ConcurrentHashMap<String, RequestPool>> ipRequestPools     = Collections.unmodifiableMap(
            _ipRequestPools);
    @Getter
    private static final Map<String, ConcurrentHashMap<String, RequestPool>> userIdRequestPools = Collections.unmodifiableMap(
            _userIdRequestPools);

    @JsonIgnore
    private static final Map<LimitMeta, List<RequestPool>> associatedIpPoolsCache = new HashMap<>();

    public static RequestPool getIpRequestPools(String api,
                                                String method) {
        ConcurrentHashMap<String, RequestPool> map = _ipRequestPools.get(api);
        if (map == null) return null;
        return map.get(method);
    }

    public static RequestPool getUserIdRequestPool(String api,
                                                   String method) {
        ConcurrentHashMap<String, RequestPool> map = _userIdRequestPools.get(api);
        if (map == null) return null;
        return map.get(method);
    }

    public static class RequestPools extends HashMap<String, ConcurrentHashMap<String, RequestPool>> {
        private static final long serialVersionUID = -1838299980303412207L;
    }

    public static class RequestPool extends ConcurrentHashMap<String, RequestMeta> {
        private static final long serialVersionUID = -284927742264879191L;
    }

    public static LimitMeta getLimitMetadata(String method,
                                             String api) {
        Map<String, LimitMeta> limitMetaMap = _rateLimitMetadata.get(api);
        if (limitMetaMap == null) return null;
        return limitMetaMap.get(method);
    }

    public static void setPathPattern(String pattern) {
        pathMatcherMap.put(pattern, pathPatternParser.parse(pattern));
    }

    public static boolean match(String pattern,
                                String path) {
        PathPattern pathPattern = pathMatcherMap.get(pattern);
        if (pathPattern == null) return false;
        return pathPattern.matches(PathContainer.parsePath(path));
    }

    public static String getPattern(String path) {
        for (Map.Entry<String, PathPattern> entry : pathMatcherMap.entrySet()) {
            if (entry.getValue().matches(PathContainer.parsePath(path))) {
                return entry.getKey();
            }
        }
        return null;
    }

    public static String getPattern(String method,
                                    String path) {
        for (Map.Entry<String, PathPattern> entry : pathMatcherMap.entrySet()) {
            if (entry.getValue().matches(PathContainer.parsePath(path))) {
                ConcurrentHashMap<String, RequestPool> map = _ipRequestPools.get(entry.getKey());
                if (map == null || map.isEmpty()) return null;
                if (map.get(method) == null) return null;
                return entry.getKey();
            }
        }
        return null;
    }

    public static void receive(RequestMessage requestMessage) {
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
            Httpd.RequestPool ipRequestPool     = _ipRequestPools.get(api).get(method);
            Httpd.RequestPool userIdRequestPool = _userIdRequestPools.get(api).get(method);
            RequestMeta requestMeta = checkType.equals(IP) ? ipRequestPool.get(ip) : userIdRequestPool.get(
                    userId.toString());
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

    public static List<Httpd.RequestPool> associatedIpPools(LimitMeta limitMeta) {
        List<Httpd.RequestPool> rps = associatedIpPoolsCache.get(limitMeta);
        if (rps != null) return rps;

        List<LimitMeta.AssociatedPattern> associatedPatterns = limitMeta._getAssociatedPatterns();
        RateLimit.CheckType               checkType          = limitMeta.getCheckType();
        List<Httpd.RequestPool>           oIpPools           = new ArrayList<>();
        if (associatedPatterns != null) {
            associatedPatterns.forEach(associatedPattern -> associatedPattern.getMethods().forEach(meth -> {
                RequestPools requestPools = checkType.equals(IP) ? _ipRequestPools : _userIdRequestPools;
                requestPools.keySet().stream().filter(path -> match(associatedPattern.getPattern(), path)).forEach(
                        path -> oIpPools.add(requestPools.get(path).get(meth)));
            }));
        }

        associatedIpPoolsCache.put(limitMeta, oIpPools);
        return oIpPools;
    }

    public static void forbid(long now,
                              RequestMeta requestMeta,
                              LimitMeta limitMeta,
                              String method,
                              String api) {
        requestMeta.forbidden(method, api, limitMeta);
        String ip     = requestMeta.getIp();
        Object userId = requestMeta.getUserId();
        for (Httpd.RequestPool ipPool : associatedIpPools(limitMeta)) {
            if (!ipPool.containsKey(ip)) {
                ipPool.put(ip, new RequestMeta(now, ip, userId).forbidden(method, api, limitMeta));
            } else {ipPool.get(ip).forbidden(method, api, limitMeta);}
        }
    }

    public static void relive(RequestMeta requestMeta,
                              LimitMeta limitMeta,
                              String method,
                              String api) {
        String ip = requestMeta.getIp();
        requestMeta.relive(method, api, limitMeta);
        associatedIpPools(limitMeta).forEach(ipPool -> {
            if (ipPool.containsKey(ip)) ipPool.get(ip).relive(method, api, limitMeta);
        });
    }

    @Nullable
    public static synchronized Object modify(@NonNull AuthzModifier authzModifier) {
        try {
            switch (authzModifier.getOperate()) {
                case ADD:
                case MODIFY:
                case UPDATE:
                    AuthzModifier.RateLimitInfo rateLimit = authzModifier.getRateLimit();
                    LimitMeta limitMeta = new LimitMeta(rateLimit.getWindow(), rateLimit.getMaxRequests(),
                                                        rateLimit.getPunishmentTime().toArray(new String[0]),
                                                        rateLimit.getMinInterval(),
                                                        rateLimit.getAssociatedPatterns().toArray(new String[0]),
                                                        rateLimit.getCheckType());
                    _rateLimitMetadata.get(authzModifier.getApi()).put(authzModifier.getMethod(), limitMeta);
                    return limitMeta;
                case DEL:
                case DELETE:
                    return _rateLimitMetadata.get(authzModifier.getApi()).remove(authzModifier.getMethod());
                case READ:
                case GET:
                    return _rateLimitMetadata.get(authzModifier.getApi()).get(authzModifier.getMethod());
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

    private static boolean isInit = false;

    public static void init(AuthzProperties properties,
                            ApplicationContext applicationContext,
                            Map<RequestMappingInfo, HandlerMethod> mapRet) {
        if (isInit) return;
        isInit = true;
        HashMap<String, LimitMeta> cMap = new HashMap<>();

        applicationContext.getBeansWithAnnotation(RateLimit.class).forEach((key, value) -> {
            Class<?>  aClass    = AopUtils.getTargetClass(value);
            RateLimit rateLimit = aClass.getAnnotation(RateLimit.class);
            if (rateLimit != null) {
                cMap.put(aClass.getName(),
                         new LimitMeta(rateLimit.window(),
                                       rateLimit.maxRequests(),
                                       rateLimit.punishmentTime(),
                                       rateLimit.minInterval(),
                                       rateLimit.associatedPatterns(),
                                       rateLimit.checkType()));
            }
        });

        mapRet.forEach((key, value) -> {
            Set<RequestMethod> methods   = key.getMethodsCondition().getMethods();
            RateLimit          rateLimit = value.getMethodAnnotation(RateLimit.class);
            if (rateLimit != null) {
                LimitMeta limitMeta = new LimitMeta(rateLimit.window(),
                                                    rateLimit.maxRequests(),
                                                    rateLimit.punishmentTime(),
                                                    rateLimit.minInterval(),
                                                    rateLimit.associatedPatterns(),
                                                    rateLimit.checkType());
                methods.forEach(
                        method -> getPatterns(key).forEach(
                                patternValue -> _rateLimitMetadata.computeIfAbsent(patternValue,
                                                                                   r -> new HashMap<>()).put(
                                        method.toString(), limitMeta))
                );
            } else {
                methods.forEach(
                        method -> {
                            getPatterns(key).forEach(
                                    patternValue -> {
                                        LimitMeta limitMeta = cMap.get(value.getBeanType().getName());
                                        if (limitMeta != null) {
                                            _rateLimitMetadata
                                                    .computeIfAbsent(patternValue, r -> new HashMap<>()).put(
                                                            method.toString(), limitMeta);
                                        }
                                    });
                        });
            }

            getPatterns(key).forEach(patternValue -> {
                setPathPattern(patternValue);
                HashMap<String, Httpd.RequestPool> userIdRequestPool = new HashMap<>();
                HashMap<String, Httpd.RequestPool> ipRequestPool     = new HashMap<>();

                key.getMethodsCondition().getMethods().forEach(method -> {
                    userIdRequestPool.put(method.name(), new Httpd.RequestPool());
                    ipRequestPool.put(method.name(), new Httpd.RequestPool());
                });

                _ipRequestPools.computeIfAbsent(patternValue, r -> new ConcurrentHashMap<>()).putAll(
                        ipRequestPool);
                _userIdRequestPools.computeIfAbsent(patternValue, r -> new ConcurrentHashMap<>()).putAll(
                        userIdRequestPool);
            });
        });

        ignoreSuffix = properties.getIgnoreSuffix();
    }

}
