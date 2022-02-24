package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.Scheduler;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import static cn.omisheep.commons.util.Utils.castValue;

/**
 * Injected into the Spring container
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 2022-02-01
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Slf4j
public class DoubleDeckCache implements Cache {

    final LoadingCache<String, CacheItem> cache;

    public DoubleDeckCache(AuthzProperties properties) {
        Caffeine<String, CacheItem> caffeine = Caffeine.newBuilder()
                .scheduler(Scheduler.systemScheduler())
                .expireAfter(new CacheExpiry(TimeUtils.parseTimeValue(properties.getCache().getExpireAfterReadOrUpdateTime()), TimeUnit.MILLISECONDS));
        Long cacheMaximumSize = properties.getCache().getCacheMaximumSize();
        if (cacheMaximumSize != null)
            caffeine.maximumSize(cacheMaximumSize);
        cache = caffeine.build(new CacheLoader<String, CacheItem>() {
            @Override
            public @Nullable CacheItem load(@NonNull String key) {
                Object o = RedisUtils.Obj.get(key); // cache中没有，加载redis
                long ttl = RedisUtils.ttl(key);
                if (o != null) { // redis中有 且值不为空
                    return new CacheItem(ttl, o);
                } else if (ttl != -2) { // redis中有 但值为空
                    // 如果这个key存在，则说明 key->"" 而不是 key->nil
                    return new CacheItem(ttl, null);
                }
                return null; // redis中也没有
            }

            @Override
            public @NonNull Map<@NonNull String, @NonNull CacheItem> loadAll(@NonNull Iterable<? extends @NonNull String> keys) {
                List<String> list = new ArrayList<>();
                keys.forEach(list::add);
                List objects = RedisUtils.Obj.get(list);
                HashMap<String, CacheItem> map = new HashMap<>();
                Iterator<? extends @NonNull String> iterator = keys.iterator();
                for (Object o : objects) {
                    String key = iterator.next();
                    long ttl = RedisUtils.ttl(key);
                    if (o != null) { // redis中有 且值不为空
                        map.put(key, new CacheItem(ttl, o));
                    } else if (ttl != -2) { // redis中有 但值为空
                        // 如果这个key存在，则说明 key->"" 而不是 key->nil
                        map.put(key, new CacheItem(ttl, null));
                    }
                }
                return map;
            }
        });
    }

    @Override
    public Set<String> keys(String pattern) {
        CacheItem cacheItem = cache.asMap().get(pattern);
        if (cacheItem != null) return (Set<String>) cacheItem.value;
        Set<String> scan = RedisUtils.scan(pattern);
        RedisUtils.publish(Cache.CHANNEL, Message.write(pattern, scan));
        if (!scan.isEmpty()) cache.put(pattern, new CacheItem(scan));
        return scan;
    }

    @Override
    public Set<String> keysAndLoad(String pattern) {
        Set<String> keys = keys(pattern);
        cache.getAll(keys);
        return keys;
    }

    @Override
    public boolean hasKey(String key) {
        return key != null && cache.get(key) != null;
    }

    @Override
    public long ttl(String key) {
        return RedisUtils.ttl(key);
    }

    @Override
    public @Nullable Object get(String key) {
        CacheItem item = cache.get(key);
        return item != null ? item.value : null;
    }

    @Override
    public @NonNull Map<String, Object> get(Set<String> keys) {
        return new HashMap<>(cache.getAll(keys));
    }

    @Override
    public @NonNull <T> Map<String, T> get(Set<String> keys, Class<T> requiredType) {
        Map<String, CacheItem> items = cache.getAll(keys);
        HashMap<String, T> map = new HashMap<>();
        for (Map.Entry<String, CacheItem> entry : items.entrySet()) {
            map.put(entry.getKey(), castValue(entry.getValue(), requiredType));
        }
        return map;
    }


    /**
     * @param key     键
     * @param element 值
     * @param ttl     秒
     * @return 所添加的值
     */
    @Override
    public <E> E set(String key, E element, long ttl) {
        try {
            if (ttl == -1) {
                RedisUtils.Obj.update(key, element);
            } else {
                RedisUtils.Obj.set(key, element, ttl);
            }
        } catch (Exception e) {
            LogUtils.logError("{}", e.getMessage());
        } finally {
            cache.put(key, new CacheItem(ttl, element));
        }
        RedisUtils.publish(Cache.CHANNEL, Message.write(key));
        return element;
    }

    @Override
    public void del(String key) {
        cache.invalidate(key);
        Async.run(() -> {
            RedisUtils.Obj.del(key);
            RedisUtils.publish(Cache.CHANNEL, Message.delete(key));
        });
    }

    @Override
    public void del(Set<String> keys) {
        cache.invalidateAll(keys);
        Async.run(() -> {
            RedisUtils.Obj.del(keys);
            RedisUtils.publish(Cache.CHANNEL, Message.delete(keys));
        });
    }

    @Override
    public void receive(Message message) {
        if (Message.MessageType.WRITE.equals(message.getType())) {
            setSync(message);
        } else {
            delSync(message.getKeys());
        }
    }

    private void setSync(Message message) {
        Set<String> keys = message.getKeys();
        if (keys.size() == 1) {
            String key = CollectionUtils.resolveSingletonSet(keys);
            Object o = RedisUtils.Obj.get(key);
            long ttl = RedisUtils.ttl(key);
            if (ttl != -2) {
                cache.put(key, new CacheItem(ttl, o));
            } else cache.invalidate(key);
        } else if (keys.size() > 1) {
            String pattern = message.getPattern();
            if (pattern == null) return;
            cache.put(pattern, new CacheItem(keys));
        }

    }

    private void delSync(Set<String> keys) {
        if (keys == null || keys.isEmpty()) return;
        cache.invalidateAll(keys);
    }

    @Override
    public void reload() {
        ConcurrentMap<String, CacheItem> map = cache.asMap();
        for (Map.Entry<String, CacheItem> next : map.entrySet()) {
            String key = next.getKey();
            CacheItem<Object> item = new CacheItem<>(RedisUtils.ttl(next.getKey()), RedisUtils.Obj.get(next.getKey()));
            map.remove(key);
            map.put(key, item);
        }
    }
}
