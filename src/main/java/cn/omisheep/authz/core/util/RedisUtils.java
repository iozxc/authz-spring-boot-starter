package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.cache.Message;
import cn.omisheep.commons.util.Assert;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.Utils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.data.redis.connection.*;
import org.springframework.data.redis.connection.jedis.JedisClusterConnection;
import org.springframework.data.redis.connection.jedis.JedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceClusterConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnection;
import org.springframework.data.redis.core.*;

import java.time.Duration;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@SuppressWarnings("unchecked")
@Slf4j
public class RedisUtils {

    // ================================ common ================================ //

    /**
     * keys在每次扫描redis时会让redis阻塞，所以不推荐使用keys
     * 推荐使用scan
     *
     * @param pattern pattern
     * @return 匹配上的keys
     */
    public static Set<String> keys(String pattern) {
        return redisTemplate.keys(pattern);
    }

    /**
     * scan方法，用于代替keys，
     *
     * @param pattern pattern
     * @return 匹配上的keys
     */
    @SneakyThrows
    public static Set<String> scan(String pattern) {
        RedisConnectionFactory connectionFactory = redisTemplate.getConnectionFactory();
        if (connectionFactory == null) return new HashSet<>();
        Set<String> keys = new HashSet<>();
        RedisConnection connection = connectionFactory.getConnection();
        Cursor<byte[]> scan;
        if (connection instanceof JedisClusterConnection || connection instanceof LettuceClusterConnection) {
            RedisClusterConnection clusterConnection = connectionFactory.getClusterConnection();
            for (RedisClusterNode next : clusterConnection.clusterGetNodes()) {
                scan = clusterConnection.scan(next, ScanOptions.scanOptions().match(pattern).count(SCAN_COUNT).build());
                while (scan.hasNext()) keys.add(new String(scan.next()));
                scan.close();
            }
            return keys;
        }
        if (connection instanceof JedisConnection || connection instanceof LettuceConnection) {
            scan = connection.scan(ScanOptions.scanOptions().match(pattern).count(SCAN_COUNT).build());
            while (scan.hasNext()) keys.add(new String(scan.next()));
            scan.close();
            return keys;
        }
        return new HashSet<>();
    }

    public static boolean expire(String key, String timeVal) {
        return expire(key, TimeUtils.parseTimeValue(timeVal));
    }

    public static boolean expire(String key, long ms) {
        try {
            if (ms > 0) {
                redisTemplate.expire(key, Duration.ofMillis(ms));
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static long ttl(String key) {
        Long expire = redisTemplate.getExpire(key);
        return expire != null ? expire : 0;
    }

    public static boolean hasKey(String key) {
        Boolean bool = redisTemplate.hasKey(key);
        return bool != null && bool;
    }

    public static void publish(String channel, Object msg) {
        redisTemplate.convertAndSend(channel, msg);
    }

    public static void publish(String channel, Message message) {
        redisTemplate.convertAndSend(channel, message);
    }

    // ================================ stringRedisTemplate ================================ //

    public static class Str {
        public static void set(String key, String value) {
            stringRedisTemplate.opsForValue().set(key, value);
        }

        public static String get(String key) {
            return stringRedisTemplate.opsForValue().get(key);
        }

        public static void hset(String key, Map<Object, Object> map, long time) {
            stringRedisTemplate.opsForHash().putAll(key, map);
            expire(key, time);
        }

        public static void hset(String key, String timeVal, Map<Object, Object> map) {
            hset(key, map, TimeUtils.parseTimeValue(timeVal));
        }

        public static void hset(String key, Map<Object, Object> map) {
            stringRedisTemplate.opsForHash().putAll(key, map);
        }

        public static Map<Object, Object> hget(String key) {
            return stringRedisTemplate.opsForHash().entries(key);
        }

        public static String hget(String key, String field) {
            return (String) stringRedisTemplate.opsForHash().get(key, field);
        }

        public static void del(String key) {
            if (key != null && !key.equals("")) {
                stringRedisTemplate.delete(key);
            }
        }

        public static void del(Collection<String> collection) {
            if (collection != null && collection.size() > 0) {
                stringRedisTemplate.delete(collection);
            }
        }
    }

    // ================================ redisTemplate ================================ //

    public static class Obj {
        public static void set(String key, Object value) {
            redisTemplate.opsForValue().set(key, value);
        }

        public static void set(String key, Object value, long ttl) {
            redisTemplate.opsForValue().set(key, value, ttl, TimeUnit.SECONDS);
        }

        public static Object get(String key) {
            return redisTemplate.opsForValue().get(key);
        }

        public static <E> E get(String key, Class<E> requireType) {
            return Utils.castValue(redisTemplate.opsForValue().get(key), requireType);
        }

        public static void del(String key) {
            if (key != null && !key.equals("")) {
                redisTemplate.delete(key);
            }
        }

        public static void del(Collection<String> collection) {
            if (collection != null && collection.size() > 0) {
                redisTemplate.delete(collection);
            }
        }

        public static void update(String key, Object value) {
            redisTemplate.opsForValue().set(key, value, 0);
        }

        public static void setrange(String key, Object value, long offset) {
            redisTemplate.opsForValue().set(key, value, offset);
        }
    }

    private static final StringRedisTemplate stringRedisTemplate;
    private static final RedisTemplate<String, Object> redisTemplate;
    private static final int SCAN_COUNT;

    static {
        stringRedisTemplate = AUtils.getBean(StringRedisTemplate.class);
        redisTemplate = AUtils.getBean("redisTemplate", RedisTemplate.class);
        RedisProperties properties = AUtils.getBean(RedisProperties.class);
        AuthzProperties authzProperties = AUtils.getBean(AuthzProperties.class);
        SCAN_COUNT = authzProperties.getCache().getRedisScanCount();
        Duration timeout = properties.getTimeout();

        try {
            Object execute = stringRedisTemplate.execute((RedisCallback<Object>) RedisConnectionCommands::ping);
            Assert.state(execute != null && execute.equals("PONG"), "请配置redis并确保其能够正常连接");
        } catch (Exception e) {
            log.error("请配置redis并确保其能够正常连接");
        }

        if (timeout == null || timeout.isZero()) {
            properties.setTimeout(Duration.ofSeconds(10));
        }
    }

    private RedisUtils() {
    }

}

