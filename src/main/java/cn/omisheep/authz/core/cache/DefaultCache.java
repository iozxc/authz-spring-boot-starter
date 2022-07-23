package cn.omisheep.authz.core.cache;

import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.KeyMatchUtils;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Scheduler;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static cn.omisheep.commons.util.ClassUtils.castValue;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
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

    public DefaultCache() {
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
        return cache.asMap().keySet().stream().filter(key -> KeyMatchUtils.stringMatch(pattern, key, true)).collect(Collectors.toSet());
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
    public <E> void set(@NonNull String key, @Nullable E element, long ttl) {
        cache.put(key, new CacheItem<>(ttl, element));
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
    public @NonNull <T> Map<String, T> get(@NonNull Set<String> keys, @NonNull Class<T> requiredType) {
        Map<String, CacheItem> items = cache.getAllPresent(keys);
        HashMap<String, T>     map   = new HashMap<>();
        for (Map.Entry<String, CacheItem> entry : items.entrySet()) {
            map.put(entry.getKey(), castValue(entry.getValue(), requiredType));
        }
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

}
