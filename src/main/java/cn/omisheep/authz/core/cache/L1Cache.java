package cn.omisheep.authz.core.cache;

import cn.omisheep.commons.util.KeyMatchUtils;
import cn.omisheep.commons.util.TimeUtils;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Scheduler;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.commons.util.ClassUtils.castValue;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings({"rawtypes"})
public class L1Cache implements cn.omisheep.authz.core.cache.Cache {

    private final Cache<String, CacheItem> cache;

    public L1Cache(Long maximumSize,
                   String expireAfterCreateTime,
                   String expireAfterUpdateTime,
                   String expireAfterReadTime) {
        Caffeine<String, CacheItem> caffeine = Caffeine.newBuilder()
                .scheduler(Scheduler.systemScheduler())
                .expireAfter(new CacheExpiry(TimeUtils.parseTimeValue(expireAfterCreateTime),
                                             TimeUtils.parseTimeValue(expireAfterUpdateTime),
                                             TimeUtils.parseTimeValue(expireAfterReadTime)));
        if (maximumSize == null) {
            cache = caffeine.build();
        } else {
            cache = caffeine.maximumSize(maximumSize).build();
        }
    }

    public L1Cache() {
        cache = Caffeine.newBuilder()
                .scheduler(Scheduler.systemScheduler())
                .expireAfter(new CacheExpiry())
                .build();
    }

    @Override
    @NonNull
    public Set<String> keys(@NonNull String pattern) {
        if (pattern.equals(EMPTY)) return new HashSet<>();
        if (pattern.equals(ALL)) return cache.asMap().keySet();
        return cache.asMap().keySet().stream().filter(key -> KeyMatchUtils.stringMatch(pattern, key, true)).collect(
                Collectors.toSet());
    }

    @Override
    public boolean notKey(@NonNull String key) {
        return cache.getIfPresent(key) == null;
    }

    @Override
    public long ttl(@NonNull String key) {
        CacheItem<?> item = cache.getIfPresent(key);
        if (item == null) return -2;
        return item.ttl();
    }

    @Override
    public <E> void set(@NonNull String key,
                        @Nullable E element,
                        long ttl) {
        cache.put(key, new CacheItem<>(ttl, element));
    }

    @Override
    public void set(@NonNull Map<String, ?> elements) {
        elements.forEach((k, v) -> {
            cache.put(k, new CacheItem<>(v));
        });
    }

    @Override
    public Object get(String key) {
        CacheItem<?> item = cache.getIfPresent(key);
        return item == null ? null : item.value;
    }

    @Override
    public @NonNull Map<String, Object> get(Set<String> keys) {
        return new HashMap<>(cache.getAllPresent(keys));
    }

    @Override
    public @NonNull <T> Map<String, T> get(@NonNull Set<String> keys,
                                           @NonNull Class<T> requiredType) {
        HashMap<String, T>     map   = new HashMap<>();
        Map<String, CacheItem> items = cache.getAllPresent(keys);
        items.forEach((k, v) -> {
            if (v.value == null) {
                map.put(k, null);
            } else {
                map.put(k, castValue(v.value, requiredType));
            }
        });
        return map;
    }

    @Override
    public void del(@NonNull String key) {
        cache.invalidate(key);
    }

    @Override
    public void del(@NonNull Set<String> keys) {
        cache.invalidateAll(keys);
    }

    @Override
    @NonNull
    public Map<String, Object> asMap() {
        HashMap<String, Object> map = new HashMap<>();
        for (Map.Entry<String, CacheItem> e : cache.asMap().entrySet()) {
            map.put(e.getKey(), e.getValue().value);
        }
        return Collections.unmodifiableMap(map);
    }

    @Override
    public @NonNull Map<String, CacheItem> asRawMap() {
        return Collections.unmodifiableMap(cache.asMap());
    }
}
