package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.authz.core.util.TimeUtils;
import cn.omisheep.commons.util.CollectionUtils;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.Scheduler;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.Utils.castValue;

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
        cache = caffeine.build(key -> {
            LogUtils.logDebug("cache中没有，加载redis   key: {}");
            Object o = RedisUtils.Obj.get(key); // cache中没有，加载redis
            if (o != null) { // redis中有 且值不为空
                LogUtils.logDebug("redis中有 且值不为空   key: {}  value: {}", key, o);
                return new CacheItem(RedisUtils.ttl(key), o);
            } else { // redis中有 但值为空
                LogUtils.logDebug("redis中有 但值为空   key: {}", key);
                long ttl = RedisUtils.ttl(key); // 如果这个key存在，则说明key->""而不是key->nil
                if (ttl != -2) return new CacheItem(ttl, null);
            }
            LogUtils.logDebug("redis中也没有   key: {}", key);
            return null; // redis中也没有
        });
    }

    @Override
    public Set<String> keys(String pattern) {
        return RedisUtils.scan(pattern);
    }

    @Override
    public boolean hasKey(String key) {
        return key != null && RedisUtils.hasKey(key);
    }

    @Override
    public long ttl(String key) {
        return RedisUtils.ttl(key);
    }

    /**
     * @param key     键
     * @param element 值
     * @param ttl     秒，为-1时将继承之前的key的ttl
     * @return 所添加的值
     */
    @Override
    public <E> E set(String key, E element, long ttl) {
        cache.put(key, new CacheItem(ttl, element));
        if (ttl == -1) {
            RedisUtils.Obj.update(key, element);
        } else {
            RedisUtils.Obj.set(key, element, ttl);
        }
        RedisUtils.publish(Cache.CHANNEL, Message.write(key));
        return element;
    }

    @Override
    public Object get(String key) {
        CacheItem item = cache.get(key);
        if (item == null) return null;
        long ttl = item.ttl();
        LogUtils.logDebug("存在 key: {} ，剩余时间: {}(秒)", key, ttl == -1 ? "无限时长" : ttl);
        return item.value;
        // return item != null ? item.value : null;
    }

    @Override
    public List get(Set<String> keys) {
        Map<String, CacheItem> items = cache.getAllPresent(keys);
        return items.values().stream().map(CacheItem::getValue).collect(Collectors.toList());
    }

    @Override
    public <T> List<T> get(Set<String> keys, Class<T> requiredType) {
        Map<String, CacheItem> items = cache.getAllPresent(keys);
        return items.values().stream().map(cacheItem -> castValue(cacheItem.value, requiredType)).collect(Collectors.toList());
    }

    @Override
    public void del(String key) {
        cache.invalidate(key);
        RedisUtils.Obj.del(key);
        RedisUtils.publish(Cache.CHANNEL, Message.delete(key));
    }

    @Override
    public void del(Set<String> keys) {
        cache.invalidateAll(keys);
        RedisUtils.Obj.del(keys);
        RedisUtils.publish(Cache.CHANNEL, Message.delete(keys));
    }

    @Override
    public void sync(Message message) {
        if (Message.MessageType.WRITE.equals(message.getType())) {
            setSync(message.getKeys());
        } else {
            delSync(message.getKeys());
        }
    }

    private void setSync(Set<String> keys) {
        String key = CollectionUtils.resolveSingletonSet(keys);
        if (!hasKey(key)) return;
        Object o = RedisUtils.Obj.get(key);
        long ttl = RedisUtils.ttl(key);
        if (o != null || ttl != -2) cache.put(key, new CacheItem(ttl, o));
        else cache.invalidate(key);
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
