package cn.omisheep.authz.core.cache;

import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.Utils;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Scheduler;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static cn.omisheep.commons.util.Utils.castValue;


/**
 * @author zhouxinchen[1269670415@qq.com]
 */
@SuppressWarnings({"rawtypes"})
public class DefaultCache implements cn.omisheep.authz.core.cache.Cache {

    Cache<String, CacheItem> cache;

    public DefaultCache(Long maximumSize, String time) {
        if (maximumSize == null) {
            cache = Caffeine.newBuilder()
                    .scheduler(Scheduler.systemScheduler())
                    .expireAfter(new CacheExpiry(TimeUtils.parseTimeValue(time), TimeUnit.MILLISECONDS))
                    .build();
        } else {
            cache = Caffeine.newBuilder()
                    .scheduler(Scheduler.systemScheduler())
                    .expireAfter(new CacheExpiry(TimeUtils.parseTimeValue(time), TimeUnit.MILLISECONDS))
                    .maximumSize(maximumSize)
                    .build();
        }
    }

    public DefaultCache(String time) {
        cache = Caffeine.newBuilder()
                .scheduler(Scheduler.systemScheduler())
                .expireAfter(new CacheExpiry(TimeUtils.parseTimeValue(time), TimeUnit.MILLISECONDS))
                .build();
    }

    public DefaultCache() {
        cache = Caffeine.newBuilder()
                .scheduler(Scheduler.systemScheduler())
                .expireAfter(new CacheExpiry())
                .build();
    }

    @Override
    public Set<String> keys(String pattern) {
        if (pattern == null || pattern.equals(EMPTY)) return new HashSet<>();
        if (pattern.equals(ALL)) return cache.asMap().keySet();
        return cache.asMap().keySet().stream().filter(key -> Utils.stringMatch(pattern, key, true)).collect(Collectors.toSet());
    }

    @Override
    public boolean hasKey(String key) {
        return cache.getIfPresent(key) != null;
    }

    @Override
    public long ttl(String key) {
        CacheItem<?> item = cache.getIfPresent(key);
        if (item == null) return -2;
        return item.ttl();
    }

    @Override
    public <E> E set(String key, E element, long ttl) {
        cache.put(key, new CacheItem<>(ttl, element));
        return element;
    }

    @Override
    public Object get(String key) {
        CacheItem<?> item = cache.getIfPresent(key);
        return item == null ? null : item.value;
    }

    @Override
    public List get(Set<String> keys) {
        Map<String, CacheItem> items = cache.getAllPresent(keys);
        return items.values().stream().map(CacheItem::getValue).collect(Collectors.toList());
    }

    @Override
    public <T> List<T> get(Set<String> keys, Class<T> requiredType) {
        Map<String, CacheItem> items = cache.getAllPresent(keys);
        return items.values().stream().map(cacheItem -> castValue(cacheItem.getValue(), requiredType)).collect(Collectors.toList());
    }

    @Override
    public void del(String key) {
        cache.invalidate(key);
    }

    @Override
    public void del(Set<String> keys) {
        cache.invalidateAll(keys);
    }

}
