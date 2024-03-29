package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.msg.CacheMessage;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.KeyMatchUtils;
import cn.omisheep.commons.util.TimeUtils;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.Scheduler;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;

import static cn.omisheep.authz.core.config.Constants.USER_REQUEST;
import static cn.omisheep.commons.util.ClassUtils.castValue;

/**
 * 双层同步缓存
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class L2Cache implements Cache {

    private final LoadingCache<String, CacheItem> cache;

    private final ConcurrentSkipListSet<String> keyPatterns = new ConcurrentSkipListSet<>();

    public L2Cache(AuthzProperties properties) {
        Caffeine<String, CacheItem> caffeine = Caffeine.newBuilder().scheduler(Scheduler.systemScheduler()).expireAfter(
                new CacheExpiry(TimeUtils.parseTimeValue(properties.getCache().getExpireAfterCreateTime()),
                                TimeUtils.parseTimeValue(properties.getCache().getExpireAfterUpdateTime()),
                                TimeUtils.parseTimeValue(properties.getCache().getExpireAfterReadTime()))
        );
        Long cacheMaximumSize = properties.getCache().getCacheMaximumSize();
        if (cacheMaximumSize != null) caffeine.maximumSize(cacheMaximumSize);
        cache = caffeine.build(new CacheLoader<String, CacheItem>() {
            @Override
            public @Nullable CacheItem load(@NonNull String key) {
                return RedisUtils.Obj.get(key, CacheItem.class);
            }

            @Override
            public @NonNull Map<@NonNull String, @NonNull CacheItem> loadAll(
                    @NonNull Iterable<? extends @NonNull String> keys) {
                List<String> list = new ArrayList<>();
                keys.forEach(list::add);
                HashMap<String, CacheItem> map       = new HashMap<>();
                List<CacheItem>            valueList = RedisUtils.Obj.get(list);
                Iterator<CacheItem>        iterator  = valueList.iterator();
                list.forEach(k -> {
                    CacheItem next = iterator.next();
                    if (next == null) {
                        map.put(k, new CacheItem(null));
                    } else {
                        map.put(k, next);
                    }
                });
                return map;
            }
        });
    }

    @Override
    @NonNull
    public Set<String> keys(@NonNull String pattern) {
        if (!pattern.contains("*") && !pattern.contains("?")) return CollectionUtils.ofSet(pattern);
        CacheItem cacheItem = cache.asMap().get(pattern);
        if (cacheItem != null) return (Set<String>) cacheItem.value;
        Set<String> scan = RedisUtils.scan(pattern);
        if (pattern.startsWith(USER_REQUEST)) return scan;
        Async.run(() -> RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.write(pattern, scan)));
        if (!scan.isEmpty()) {
            cache.put(pattern, new CacheItem(scan));
            keyPatterns.add(pattern);
        }
        return scan;
    }

    @Override
    @NonNull
    public Set<String> keysAndLoad(String pattern) {
        Set<String> keys = keys(pattern);
        if (keys.isEmpty()) return new HashSet<>();
        Async.run(() -> cache.getAll(keys));
        return keys;
    }

    @Override
    public boolean notKey(@NonNull String key) {
        return cache.get(key) == null;
    }

    @Override
    public long ttl(@NonNull String key) {
        CacheItem item = cache.get(key);
        if (item == null) return -2;
        return item.ttl();
    }

    @Override
    public void expire(@NonNull String key,
                       long ms) {
        if (ms == 0 || ms < -1) cache.invalidate(key);
        CacheItem item = cache.get(key);
        if (item != null) {
            item.expiration = TimeUtils.nowTime() + ms;
            RedisUtils.expire(key, ms);
        }
    }

    /**
     * @param key     键
     * @param element 值
     * @param ttl     毫秒
     */
    @Override
    public <E> void set(@NonNull String key,
                        @Nullable E element,
                        long ttl) {
        setSneaky(key, element, ttl);
        Async.run(() -> RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.write(key)));
    }

    @Override
    public void set(@NonNull Map<String, ?> elements) {
        HashMap<String, CacheItem> items = new HashMap<>();
        elements.forEach((k, v) -> items.put(k, new CacheItem(v)));
        cache.putAll(items);

        Async.run(() -> {
            removePatterns(elements.keySet());
            RedisUtils.Obj.set(items);
            RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.write(items.keySet()));
        });
    }

    @Override
    public <E> void setSneaky(@NonNull String key,
                              @Nullable E element) {
        setSneaky(key, element, Cache.INFINITE);
    }

    @Override
    public <E> void setSneaky(@NonNull String key,
                              @Nullable E element,
                              long number,
                              @NonNull TimeUnit unit) {
        setSneaky(key, element, unit.toMillis(number));
    }

    @Override
    public <E> void setSneaky(@NonNull String key,
                              @Nullable E element,
                              long ms) {
        if (ms < -1 || ms == 0) return;
        try {
            CacheItem item = new CacheItem(ms, element);
            Async.run(() -> {
                removePatterns(key);
                if (ms == Cache.INFINITE) {
                    RedisUtils.Obj.update(key, item);
                } else {
                    RedisUtils.Obj.set(key, item, ms);
                }
            });
            cache.put(key, item);
        } catch (Exception e) {
            LogUtils.error(e);
        }
    }

    @Override
    public @Nullable Object get(String key) {
        cache.refresh(key);
        CacheItem item = cache.get(key);
        return item != null ? item.value : null;
    }

    @Override
    public @NonNull Map<String, Object> get(Set<String> keys) {
        HashMap<String, Object> map = new HashMap<>();
        if (keys.isEmpty()) return map;
        cache.getAll(keys).forEach((k, v) -> {
            cache.refresh(k);
            map.put(k, v.value);
        });
        return map;
    }

    @Override
    public @NonNull <T> Map<String, T> get(@NonNull Set<String> keys,
                                           @NonNull Class<T> requiredType) {
        HashMap<String, T> map = new HashMap<>();
        if (keys.isEmpty()) return map;
        Map<String, CacheItem> items = cache.getAll(keys);
        items.forEach((k, v) -> {
            cache.refresh(k);
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
        Async.run(() -> {
            removePatterns(key);
            RedisUtils.Obj.del(key);
            RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.delete(key));
        });
    }

    @Override
    public void del(@NonNull Set<String> keys) {
        if (keys.isEmpty()) return;
        cache.invalidateAll(keys);
        Async.run(() -> {
            RedisUtils.Obj.del(keys);
            RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.delete(keys));
            removePatterns(keys);
        });
    }

    @Override
    public void receive(@NonNull CacheMessage message) {
        if (CacheMessage.Type.WRITE.equals(message.getType())) {
            setSync(message);
        } else {
            delSync(message.getKeys());
        }
    }

    private void setSync(CacheMessage message) {
        Set<String> keys    = message.getKeys();
        String      pattern = message.getPattern();
        if (pattern != null) {
            cache.put(pattern, new CacheItem(keys));
        } else {
            if (keys == null) return;
            removePatterns(keys);
            HashMap<String, CacheItem> map       = new HashMap<>();
            List<CacheItem>            valueList = RedisUtils.Obj.get(keys);
            Iterator<CacheItem>        iterator  = valueList.iterator();
            keys.forEach(k -> {
                CacheItem next = iterator.next();
                if (next == null) removePatterns(k);
                map.put(k, next);
            });
            cache.putAll(map);
        }
    }

    private void delSync(Set<String> keys) {
        if (keys == null || keys.isEmpty()) return;
        removePatterns(keys);
        cache.invalidateAll(keys);
    }

    @Override
    public void reload() {
        reload(cache.asMap().keySet().toArray(new String[0]));
    }

    @Override
    public void reload(@NonNull String... keys) {
        if (keys == null || keys.length == 0) return;
        List<String> list = Arrays.asList(keys);
        list.forEach(cache::refresh);
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

    private void removePatterns(String key) {
        List<String> list = KeyMatchUtils.matchPatterns(key, keyPatterns);
        list.forEach(keyPatterns::remove);
        cache.invalidateAll(list);
    }

    private void removePatterns(Set<String> keys) {
        List<String> list = KeyMatchUtils.matchPatterns(keys, keyPatterns);
        list.forEach(keyPatterns::remove);
        cache.invalidateAll(list);
    }
}
