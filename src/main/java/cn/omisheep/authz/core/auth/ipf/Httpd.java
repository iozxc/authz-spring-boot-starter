package cn.omisheep.authz.core.auth.ipf;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import orestes.bloomfilter.CountingBloomFilter;
import orestes.bloomfilter.FilterBuilder;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Getter
public class Httpd {

    /**
     * 用于保存请求限制的信息
     */
    private final RequestPools requestPools = new RequestPools();

    public static class RequestPools extends HashMap<String, ConcurrentHashMap<String, RequestPool>> {
        private static final long serialVersionUID = -1838299980303412207L;
    }

    public static class RequestPool extends ConcurrentHashMap<String, RequestMeta> {
        private static final long serialVersionUID = -284927742264879191L;
    }

    /**
     * api限制访问次数信息map
     */
    private final Map<String, Map<String, LimitMeta>> rateLimitMetadata = new HashMap<>();

    @JsonIgnore
    private final HashMap<LimitMeta, List<RequestPool>> associatedIpPoolsCache = new HashMap<>();

    /**
     * 黑名单 $redis$
     */
    private final HashSet<RequestMeta> ipBlacklist = new HashSet<>();

    /**
     * ip过滤器
     */
    @JsonIgnore
    private final CountingBloomFilter<String> ipBlacklistBloomFilter =
            new FilterBuilder(1000,
                    0.001).countingBits(8).buildCountingBloomFilter();

//    /**
//     * 所有的api集合，提供快速访问
//     */
//    private final HashSet<String> paths = new HashSet<>();
//
//    /**
//     * 所有的api集合，提供快速访问，(加上contextPath)
//     */
//    private final HashSet<String> paddingPath = new HashSet<>();
//
//    /**
//     * 格式化之后的path 其中 {xx} 替换为 *
//     */
//    private final HashSet<String> patternPath = new HashSet<>();
}
