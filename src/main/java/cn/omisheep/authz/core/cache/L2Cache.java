package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.msg.CacheMessage;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.Utils;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.Scheduler;
import com.sun.javafx.collections.ObservableMapWrapper;
import com.sun.javafx.collections.UnmodifiableObservableMap;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static cn.omisheep.commons.util.Utils.castValue;

/**
 * Double Deck Cache
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class L2Cache implements Cache {

    private final LoadingCache<String, CacheItem> cache;

    private final ConcurrentSkipListSet<String> keyPatterns = new ConcurrentSkipListSet<>();

    public L2Cache(AuthzProperties properties) {
        Caffeine<String, CacheItem> caffeine         = Caffeine.newBuilder().scheduler(Scheduler.systemScheduler()).expireAfter(new CacheExpiry(TimeUtils.parseTimeValue(properties.getCache().getExpireAfterReadOrUpdateTime()), TimeUnit.MILLISECONDS));
        Long                        cacheMaximumSize = properties.getCache().getCacheMaximumSize();
        if (cacheMaximumSize != null) caffeine.maximumSize(cacheMaximumSize);
        cache = caffeine.build(new CacheLoader<String, CacheItem>() {
            @Override
            public @Nullable CacheItem load(@NonNull String key) {
                Object  o   = RedisUtils.Obj.get(key); // cache中没有，加载redis
                long    ttl = RedisUtils.ttl(key);
                boolean b   = ttl != -2;
                if (key.startsWith(Constants.USER_ROLES_KEY_PREFIX) || key.startsWith(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX)) {
                    ttl = INFINITE;
                }
                if (o != null) { // redis中有 且值不为空
                    return new CacheItem(ttl, o);
                } else if (b) { // redis中有 但值为空
                    // 如果这个key存在，则说明 key->"" 而不是 key->nil
                    return new CacheItem(ttl, null);
                }
                return null; // redis中也没有
            }

            @Override
            public @NonNull Map<@NonNull String, @NonNull CacheItem> loadAll(@NonNull Iterable<? extends @NonNull String> keys) {
                List<String> list = new ArrayList<>();
                keys.forEach(list::add);
                List                                objects  = RedisUtils.Obj.get(list);
                HashMap<String, CacheItem>          map      = new HashMap<>();
                Iterator<? extends @NonNull String> iterator = keys.iterator();
                for (Object o : objects) {
                    String  key = iterator.next();
                    long    ttl = RedisUtils.ttl(key);
                    boolean b   = ttl != -2;
                    if (key.startsWith(Constants.USER_ROLES_KEY_PREFIX) || key.startsWith(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX)) {
                        ttl = INFINITE;
                    }
                    if (o != null) { // redis中有 且值不为空
                        map.put(key, new CacheItem(ttl, o));
                    } else if (b) { // redis中有 但值为空
                        // 如果这个key存在，则说明 key->"" 而不是 key->nil
                        map.put(key, new CacheItem(ttl, null));
                    }
                }
                return map;
            }
        });
    }

    @Override
    @NonNull
    public Set<String> keys(@NonNull String pattern) {
        CacheItem cacheItem = cache.asMap().get(pattern);
        if (cacheItem != null) return (Set<String>) cacheItem.value;
        Set<String> scan = RedisUtils.scan(pattern);
        RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.write(pattern, scan));
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
        Async.run(() -> cache.getAll(keys));
        return keys;
    }

    @Override
    public boolean notKey(@NonNull String key) {
        return cache.get(key) == null;
    }

    @Override
    public long ttl(@NonNull String key) {
        return RedisUtils.ttl(key);
    }

    /**
     * @param key     键
     * @param element 值
     * @param ttl     秒
     */
    @Override
    public <E> void set(@NonNull String key, @Nullable E element, long ttl) {
        if (cache.asMap().get(key) == null) {
            Async.run(() -> {
                List<String> collect = keyPatterns.stream().filter(k -> Utils.stringMatch(k, key, false)).collect(Collectors.toList());
                cache.invalidateAll(collect);
            });
        }
        setSneaky(key, element, ttl);
        RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.write(key));
    }

    @Override
    public <E> void setSneaky(@NonNull String key, @Nullable E element, long number, @NonNull TimeUnit unit) {
        setSneaky(key, element, unit.toSeconds(number));
    }

    @Override
    public <E> void setSneaky(@NonNull String key, @Nullable E element, long ttl) {
        if (ttl == 0) return;
        try {
            if (ttl == Cache.INHERIT) {
                RedisUtils.Obj.update(key, element);
            } else {
                if (ttl == Cache.INFINITE) {
                    RedisUtils.Obj.set(key, element);
                } else {
                    RedisUtils.Obj.set(key, element, ttl);
                }
            }
        } catch (Exception e) {
            LogUtils.logError("{}", e.getMessage());
        } finally {
            cache.put(key, new CacheItem(ttl, element));
        }
    }

    @Override
    public @Nullable Object get(String key) {
        CacheItem item = cache.get(key);
        return item != null ? item.value : null;
    }

    @Override
    public @NonNull Map<String, Object> get(Set<String> keys) {
        HashMap<String, Object> map = new HashMap<>();
        cache.getAll(keys).forEach((k, v) -> map.put(k, v.value));
        return map;
    }

    @Override
    public @NonNull <T> Map<String, T> get(@NonNull Set<String> keys, @NonNull Class<T> requiredType) {
        HashMap<String, T>     map   = new HashMap<>();
        Map<String, CacheItem> items = cache.getAll(keys);
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
        Async.run(() -> {
            RedisUtils.Obj.del(key);
            RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.delete(key));
            List<String> collect = keyPatterns.stream().filter(k -> Utils.stringMatch(k, key, false)).collect(Collectors.toList());
            cache.invalidateAll(collect);
        });
    }

    @Override
    public void del(@NonNull Set<String> keys) {
        cache.invalidateAll(keys);
        Async.run(() -> {
            RedisUtils.Obj.del(keys);
            RedisUtils.publish(CacheMessage.CHANNEL, CacheMessage.delete(keys));
            List<String> collect = keyPatterns.stream().filter(k -> keys.stream().anyMatch(key -> Utils.stringMatch(k, key, false))).collect(Collectors.toList());
            cache.invalidateAll(collect);
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
            String       key     = CollectionUtils.resolveSingletonSet(keys);
            List<String> collect = keyPatterns.stream().filter(k -> Utils.stringMatch(k, key, false)).collect(Collectors.toList());
            cache.invalidateAll(collect);
            Object o   = RedisUtils.Obj.get(key);
            long   ttl = RedisUtils.ttl(key);
            if (ttl != -2) {
                cache.put(key, new CacheItem(ttl, o));
            } else cache.invalidate(key);
        }
    }

    private void delSync(Set<String> keys) {
        if (keys == null || keys.isEmpty()) return;
        List<String> collect = keyPatterns.stream().filter(k -> keys.stream().anyMatch(key -> Utils.stringMatch(k, key, false))).collect(Collectors.toList());
        cache.invalidateAll(collect);
        cache.invalidateAll(keys);
    }

    @Override
    public void reload() {
        reload(cache.asMap().keySet().toArray(new String[0]));
    }

    @Override
    public void reload(@NonNull String... keys) {
        for (String key : keys) {
            long   ttl = RedisUtils.ttl(key);
            Object o   = RedisUtils.Obj.get(key);
            if (ttl == -2) {
                del(key);
            } else if (ttl > -2) {
                set(key, o, ttl);
            }
        }
    }

    @Override
    @NonNull
    public Map<String, CacheItem> asMap() {
        return new UnmodifiableObservableMap<String, CacheItem>(new ObservableMapWrapper(cache.asMap()));
    }
}
