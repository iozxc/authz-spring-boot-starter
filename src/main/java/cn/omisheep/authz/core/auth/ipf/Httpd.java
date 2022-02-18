package cn.omisheep.authz.core.auth.ipf;

import lombok.Getter;
import orestes.bloomfilter.CountingBloomFilter;
import orestes.bloomfilter.FilterBuilder;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhou xin chen
 */
@Getter
public class Httpd {

    /**
     * 用于保存请求限制的信息 $redis$
     */
    private final RequestPools requestPools = new RequestPools();

    public static class RequestPools extends HashMap<String, HashMap<String, IpPool>> {
    }

    public static class IpPool extends ConcurrentHashMap<String, IpMeta> {
    }

    /**
     * api限制访问次数信息map
     */
    private final Map<String, Map<String, LimitMeta>> limitedMap = new HashMap<>();

    /**
     * 黑名单 $redis$
     */
    private final HashSet<IpMeta> ipBlacklist = new HashSet<>();

    /**
     * ip过滤器
     */
    private final CountingBloomFilter<String> ipBlacklistBloomFilter =
            new FilterBuilder(1000,
                    0.001).countingBits(8).buildCountingBloomFilter();

    /**
     * 所有的api集合，提供快速访问
     */
    private final HashSet<String> paths = new HashSet<>();

    /**
     * 所有的api集合，提供快速访问，(加上contextPath)
     */
    private final HashSet<String> paddingPath = new HashSet<>();

    /**
     * 格式化之后的path 其中 {xx} 替换为 *
     */
    private final HashSet<String> patternPath = new HashSet<>();
}
