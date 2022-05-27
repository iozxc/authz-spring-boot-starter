package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.auth.AuthzModifiable;
import cn.omisheep.authz.core.auth.AuthzModifier;
import cn.omisheep.authz.core.msg.RequestMessage;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import orestes.bloomfilter.CountingBloomFilter;
import orestes.bloomfilter.FilterBuilder;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.AntPathMatcher;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class Httpd implements AuthzModifiable {

    public static final AntPathMatcher antPathMatcher = new AntPathMatcher("/");

    @Getter
    @Setter
    private String[] ignoreSuffix;

    /**
     * 用于保存请求限制的信息
     */
    @Getter
    private final RequestPools requestPools = new RequestPools();

    /**
     * api限制访问次数信息map
     */
    @Getter
    private final Map<String, Map<String, LimitMeta>> rateLimitMetadata = new HashMap<>();

    @JsonIgnore
    private final HashMap<LimitMeta, List<RequestPool>> associatedIpPoolsCache = new HashMap<>();

    /**
     * 黑名单 $redis$
     */
    @Getter
    private final HashSet<RequestMeta> ipBlacklist = new HashSet<>();

    /**
     * ip过滤器
     */
    @JsonIgnore
    @Getter
    private final CountingBloomFilter<String> ipBlacklistBloomFilter =
            new FilterBuilder(1000,
                    0.001).countingBits(8).buildCountingBloomFilter();

    public static class RequestPools extends HashMap<String, ConcurrentHashMap<String, RequestPool>> {
        private static final long serialVersionUID = -1838299980303412207L;
    }

    public static class RequestPool extends ConcurrentHashMap<String, RequestMeta> {
        private static final long serialVersionUID = -284927742264879191L;
    }

    public void receive(RequestMessage requestMessage) {
        String api    = requestMessage.getApi();
        String method = requestMessage.getMethod();
        String ip     = requestMessage.getIp();
        long   now    = requestMessage.getNow();
        try {
            RequestPool requestPool = requestPools.get(method).get(api);
            RequestMeta requestMeta = requestPool.get(ip);
            if (requestMeta == null) requestPool.put(ip, new RequestMeta(now, ip));
            else {
                LimitMeta limitMeta = rateLimitMetadata.get(method).get(api);
                if (!requestMeta.pushRequest(now, limitMeta)) {
                    forbid(now, requestMeta, limitMeta);
                }
            }
        } catch (Exception ignore) {
        }
    }

    public List<Httpd.RequestPool> associatedIpPools(LimitMeta limitMeta) {
        List<Httpd.RequestPool> rps = associatedIpPoolsCache.get(limitMeta);
        if (rps != null) return rps;

        List<LimitMeta.AssociatedPattern> associatedPatterns = limitMeta.getAssociatedPatterns();
        List<Httpd.RequestPool>           oIpPools           = new ArrayList<>();
        if (associatedPatterns != null) {
            associatedPatterns.forEach(associatedPattern ->
                    associatedPattern.getMethods().forEach(meth -> {
                        ConcurrentHashMap<String, Httpd.RequestPool> map = requestPools
                                .get(meth);
                        if (map != null) {
                            map.keySet()
                                    .stream().filter(path -> antPathMatcher.match(associatedPattern.getPattern(), path))
                                    .forEach(path -> oIpPools.add(map.get(path)));
                        }
                    })
            );
        }

        associatedIpPoolsCache.put(limitMeta, oIpPools);
        return oIpPools;
    }

    public void forbid(long now, RequestMeta requestMeta, LimitMeta limitMeta) {
        requestMeta.forbidden(limitMeta.getPunishmentTime());
        String ip = requestMeta.getIp();
        for (Httpd.RequestPool ipPool : associatedIpPools(limitMeta)) {
            if (!ipPool.containsKey(ip)) {
                ipPool.put(ip, new RequestMeta(now, ip).forbidden(limitMeta.getPunishmentTime()));
            } else ipPool.get(ip).forbidden(limitMeta.getPunishmentTime());
        }
    }

    public void relive(RequestMeta requestMeta, LimitMeta limitMeta) {
        requestMeta.relive();
        String ip = requestMeta.getIp();
        associatedIpPools(limitMeta).forEach(ipPool -> {
            if (ipPool.containsKey(ip)) ipPool.get(ip).relive();
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
                    LimitMeta limitMeta = new LimitMeta(rateLimit.getWindow(),
                            rateLimit.getMaxRequests(),
                            rateLimit.getPunishmentTime().toArray(new String[0]),
                            rateLimit.getMinInterval(),
                            rateLimit.getAssociatedPatterns().toArray(new String[0]),
                            rateLimit.getBannedType());
                    rateLimitMetadata.get(authzModifier.getMethod()).put(authzModifier.getApi(), limitMeta);
                    return limitMeta;
                case DEL:
                case DELETE:
                    return rateLimitMetadata.get(authzModifier.getMethod()).remove(authzModifier.getApi());
                case READ:
                case GET:
                    return rateLimitMetadata.get(authzModifier.getMethod()).get(authzModifier.getApi());
                default:
                    return Result.FAIL;
            }
        } catch (Exception e) {
            return Result.FAIL;
        }
    }
}
