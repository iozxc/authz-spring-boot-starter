package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.core.msg.CacheMessage;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import com.github.benmanes.caffeine.cache.Expiry;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.checkerframework.checker.index.qual.NonNegative;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static cn.omisheep.commons.util.ClassUtils.castValue;


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings({"rawtypes,", "uncheked", "unused"})
public interface Cache {

    String ALL       = "*";
    String EMPTY     = "";
    String SEPARATOR = ":";
    long   INFINITE  = -1;
    long   FOREVER   = Integer.MAX_VALUE;

    class CacheItem<E> {
        // 到期的时间，用毫秒表示
        protected final long   expiration;
        @Getter
        protected       Object value;

        public CacheItem() {
            this.expiration = INFINITE;
        }

        /**
         * @param ttl   存活时间 单位秒
         * @param value 值
         */
        public CacheItem(long ttl, E value) {
            if (ttl == INFINITE) this.expiration = -1;
            else this.expiration = TimeUtils.nowTime() + ttl * 1000L;
            this.value = value;
        }

        public CacheItem(E value) {
            this(INFINITE, value);
        }

        /**
         * 返回的ttl值 秒
         *
         * @return 秒
         */
        public long ttl() {
            if (expiration == -1) return INFINITE;
            return TimeUnit.MILLISECONDS.toSeconds(expiration - TimeUtils.nowTime());
        }

        /**
         * @param expireNanos L2缓存内存活时间
         * @return 过期前所存活的时间
         */
        public long expireAfterNanos(long expireNanos) {
            if (expiration == -1) return expireNanos;
            return Math.min(TimeUnit.MILLISECONDS.toNanos(expiration - TimeUtils.nowTime()), expireNanos);
        }

    }

    /**
     * 默认的cache缓存的过期删除策略
     */
    @Setter
    @Accessors(chain = true)
    class CacheExpiry implements Expiry<String, CacheItem> {
        private long expireAfterCreateTime;
        private long expireAfterUpdateTime;
        private long expireAfterReadTime;

        public CacheExpiry(long expireAfterCreateTime, long expireAfterUpdateTime, long expireAfterReadTime) {
            this.expireAfterCreateTime = TimeUnit.MILLISECONDS.toNanos(expireAfterCreateTime);
            this.expireAfterUpdateTime = TimeUnit.MILLISECONDS.toNanos(expireAfterUpdateTime);
            this.expireAfterReadTime   = TimeUnit.MILLISECONDS.toNanos(expireAfterReadTime);
        }

        public CacheExpiry() {
            this(Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE);
        }

        @Override
        public long expireAfterCreate(@NonNull String s, @NonNull CacheItem eCacheItem, long currentTime) {
            return eCacheItem.expireAfterNanos(expireAfterCreateTime);
        }

        @Override
        public long expireAfterUpdate(@NonNull String s, @NonNull CacheItem eCacheItem, long currentTime,
                                      @NonNegative long currentDuration) {
            return eCacheItem.expireAfterNanos(expireAfterUpdateTime);

        }

        @Override
        public long expireAfterRead(@NonNull String s, @NonNull CacheItem eCacheItem, long currentTime,
                                    @NonNegative long currentDuration) {
            return eCacheItem.expireAfterNanos(expireAfterReadTime);
        }
    }

    /**
     * @param pattern redis 风格的匹配
     * @return 匹配上的key
     */
    @NonNull Set<String> keys(@NonNull String pattern);

    /**
     * 返回匹配的key同时将对应的object加载进缓存
     *
     * @param pattern redis 风格的匹配
     * @return 匹配上的key
     */
    @NonNull
    default Set<String> keysAndLoad(String pattern) {
        return keys(pattern);
    }

    /**
     * get(key)!=null并不能判断是否有这个key，因为这个Cache可以存null
     *
     * @param key key
     * @return 如果没有这个key，返回true
     */
    boolean notKey(@NonNull String key);

    /**
     * 获取key的过期时间。如果key存在过期时间，返回剩余生存时间(秒)；
     * <p>
     * 如果key是永久的，返回-1；
     * <p>
     * 如果key不存在或者已过期，返回-2。
     *
     * @param key key
     * @return ttl 秒
     */
    long ttl(@NonNull String key);

    /**
     * @param key     键
     * @param element 值
     * @param ttl     秒，为-1时将继承之前的key的ttl ,  {@link Cache#INFINITE} 为永久存在
     * @param <E>     值的类型
     */
    <E> void set(@NonNull String key, @Nullable E element, long ttl);

    /**
     * 批量插入，时间为永久
     *
     * @param elements 键
     */
    void set(@NonNull Map<String, ?> elements);

    /**
     * @param key     键
     * @param element 值
     * @param ttl     秒，为-1时将继承之前的key的ttl ,  {@link Cache#INFINITE} 为永久存在
     * @param <E>     值的类型
     */
    default <E> void setSneaky(@NonNull String key, @Nullable E element, long ttl) {
        set(key, element, ttl);
    }

    /**
     * 注意，在这里添加缓存时，如果原key存在过期时间，当再次添加同key的值时，不会清空之前的ttl
     *
     * @param key     键
     * @param element 值
     * @param <E>     Type
     */
    default <E> void set(@NonNull String key, @Nullable E element) {
        set(key, element, INFINITE);
    }

    /**
     * @param key     键
     * @param element 值
     * @param number  存活的时间数值
     * @param unit    存活的时间单位
     * @param <E>     值的类型
     */
    default <E> void set(@NonNull String key, @Nullable E element, long number, @NonNull TimeUnit unit) {
        set(key, element, unit.toSeconds(number));
    }

    /**
     * @param key     键
     * @param element 值
     * @param number  存活的时间数值
     * @param unit    存活的时间单位
     * @param <E>     值的类型
     */
    default <E> void setSneaky(@NonNull String key, @Nullable E element, long number, @NonNull TimeUnit unit) {
        set(key, element, unit.toSeconds(number));
    }

    /**
     * @param key     键
     * @param element 值
     * @param ttl     存活的时间 "字符串类型" example：1s、10s、1m、2d
     * @param <E>     值的类型
     */
    default <E> void set(@NonNull String key, @Nullable E element, @NonNull String ttl) {
        set(key, element, TimeUtils.parseTimeValueToSecond(ttl));
    }

    /**
     * 得到对应key的值
     * get(key)!=null并不能判断是否有这个key，因为这个Cache可以存null
     * 若需要判断请用{@link #notKey(String)}
     *
     * @param key key
     * @return value
     */
    @Nullable
    Object get(String key);

    /**
     * 得到对应key的值
     *
     * @param key          key
     * @param requiredType 需要转换的类型
     * @param <T>          需要转换的类型
     * @return value
     */
    @Nullable
    default <T> T get(@NonNull String key, @NonNull Class<T> requiredType) {
        return castValue(get(key), requiredType);
    }

    @NonNull
    default Map<String, Object> getByPattern(@NonNull String pattern) {
        return get(keysAndLoad(pattern));
    }

    @NonNull
    default <T> Map<String, T> getByPattern(@NonNull String pattern, @NonNull Class<T> requiredType) {
        return get(keysAndLoad(pattern), requiredType);
    }

    default List<Object> listByPattern(@NonNull String pattern) {
        return new ArrayList<>(get(keysAndLoad(pattern)).values());
    }

    default <T> List<T> listByPattern(@NonNull String pattern, @NonNull Class<T> requiredType) {
        return new ArrayList<>(get(keysAndLoad(pattern), requiredType).values());
    }

    /**
     * @param keys keys
     * @return 返回keys的所有值
     */
    @NonNull
    Map<String, Object> get(Set<String> keys);

    /**
     * @param keys         keys
     * @param requiredType 需要转换的类型
     * @param <T>          需要转换的类型
     * @return values
     */
    @NonNull <T> Map<String, T> get(@NonNull Set<String> keys, @NonNull Class<T> requiredType);

    /**
     * @param key 需要删除的key
     */
    void del(@NonNull String key);

    /**
     * @param keys keys
     */
    void del(@NonNull Set<String> keys);

    default void del(@NonNull Collection<String> keys) {
        if (keys instanceof Set) del((Set<String>) keys);
        else del(new HashSet<>(keys));
    }

    default void del(@NonNull String... keys) {
        del(CollectionUtils.ofSet(keys));
    }

    @NonNull
    Map<String, CacheItem> asRawMap();

    @NonNull
    Map<String, Object> asMap();

    default void receive(@NonNull CacheMessage message) {
    }

    default void reload() {
    }

    default void reload(@NonNull String... keys) {
    }

    @SuppressWarnings("all")
    default void reload(@NonNull Collection<String> keys) {
        reload(keys.toArray(new String[0]));
    }

}
