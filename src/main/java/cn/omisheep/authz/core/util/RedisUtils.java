package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.msg.Message;
import cn.omisheep.commons.util.Assert;
import cn.omisheep.commons.util.ClassUtils;
import cn.omisheep.commons.util.TimeUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.data.redis.connection.*;
import org.springframework.data.redis.connection.jedis.JedisClusterConnection;
import org.springframework.data.redis.connection.jedis.JedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceClusterConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnection;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static cn.omisheep.commons.util.ClassUtils.castValue;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings({"unchecked", "rawtypes"})
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
        try {
            return redisTemplate.keys(pattern);
        } catch (Exception e) {
            return new HashSet<>();
        }
    }

    /**
     * scan方法，用于代替keys，
     *
     * @param pattern pattern
     * @return 匹配上的keys
     */
    @SneakyThrows
    public static Set<String> scan(String pattern) {
        try {
            RedisConnectionFactory connectionFactory = redisTemplate.getConnectionFactory();
            if (connectionFactory == null) return new HashSet<>();
            Set<String>     keys       = new HashSet<>();
            RedisConnection connection = connectionFactory.getConnection();
            Cursor<byte[]>  scan;
            if (connection instanceof JedisClusterConnection || connection instanceof LettuceClusterConnection) {
                RedisClusterConnection clusterConnection = connectionFactory.getClusterConnection();
                for (RedisClusterNode next : clusterConnection.clusterGetNodes()) {
                    scan = clusterConnection.scan(next,
                                                  ScanOptions.scanOptions().match(pattern).count(SCAN_COUNT).build());
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
        } catch (Exception e) {
            // skip
        }
        return new HashSet<>();
    }

    public static boolean expire(String key,
                                 String timeVal) {
        return expire(key, TimeUtils.parseTimeValue(timeVal));
    }

    public static boolean expire(String key,
                                 long ms) {
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
        try {
            Long expire = redisTemplate.getExpire(key);
            return expire != null ? expire : -2;
        } catch (Exception e) {
            return -2;
        }
    }

    public static boolean hasKey(String key) {
        try {
            Boolean bool = redisTemplate.hasKey(key);
            return bool != null && bool;
        } catch (Exception e) {
            return false;
        }
    }

    public static void publish(String channel,
                               Message message) {
        try {
            LogUtils.debug("time: {} message: {}", TimeUtils.nowTime(), message);
            redisTemplate.convertAndSend(channel, message);
        } catch (Exception e) {
            // skip
        }
    }

    // ================================ redisTemplate ================================ //

    public static class Obj {
        public static void set(String key,
                               Object value) {
            try {
                redisTemplate.opsForValue().set(key, value);
            } catch (Exception e) {
                // skip
            }
        }

        public static void set(String key,
                               Object value,
                               long ms) {
            try {
                redisTemplate.opsForValue().set(key, value, ms, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                // skip
            }
        }

        public static void set(Map<String, ?> map) {
            try {
                redisTemplate.opsForValue().multiSet(map);
            } catch (Exception e) {
                // skip
            }
        }

        public static Object get(String key) {
            try {
                return redisTemplate.opsForValue().get(key);
            } catch (Exception e) {
                return null;
            }
        }

        public static <E> E get(String key,
                                Class<E> requiredType) {
            try {
                return ClassUtils.castValue(redisTemplate.opsForValue().get(key), requiredType);
            } catch (Exception e) {
                return null;
            }
        }

        public static List get(Collection<String> key) {
            try {
                List objects = redisTemplate.opsForValue().multiGet(key);
                if (objects == null) return new ArrayList<>();
                return objects;
            } catch (Exception e) {
                return new ArrayList();
            }
        }

        public static Map<String, Object> getToMap(Collection<String> key) {
            try {
                List<?> objects = redisTemplate.opsForValue().multiGet(key);
                if (objects == null) return new HashMap<>();
                HashMap<String, Object> map      = new HashMap<>();
                Iterator<String>        iterator = key.iterator();
                for (Object value : objects) {
                    map.put(iterator.next(), value);
                }
                return map;
            } catch (Exception e) {
                return new HashMap<>();
            }

        }

        public static <E> Map<String, E> getToMap(Collection<String> key,
                                                  Class<E> requiredType) {
            try {
                List<?> objects = redisTemplate.opsForValue().multiGet(key);
                if (objects == null) return new HashMap<>();
                HashMap<String, E> map      = new HashMap<>();
                Iterator<String>   iterator = key.iterator();
                for (Object value : objects) {
                    map.put(iterator.next(), castValue(value, requiredType));
                }
                return map;
            } catch (Exception e) {
                return new HashMap<>();
            }
        }

        public static void del(String key) {
            try {
                if (key != null && !key.equals("")) {
                    redisTemplate.delete(key);
                }
            } catch (Exception e) {
                // skip
            }
        }

        public static void del(Collection<String> collection) {
            try {
                if (collection != null && collection.size() > 0) {
                    redisTemplate.delete(collection);
                }
            } catch (Exception e) {
                // skip
            }

        }

        public static void update(String key,
                                  Object value) {
            try {
                redisTemplate.opsForValue().set(key, value, 0);
            } catch (Exception e) {
                // skip
            }
        }

    }

    private static final RedisTemplate<String, Object> redisTemplate;
    private static final int                           SCAN_COUNT;

    static {
        redisTemplate = AUtils.getBean("authzRedisTemplate", RedisTemplate.class);
        RedisProperties properties      = AUtils.getBean(RedisProperties.class);
        AuthzProperties authzProperties = AUtils.getBean(AuthzProperties.class);
        SCAN_COUNT = authzProperties.getCache().getRedisScanCount();
        Duration timeout = properties.getTimeout();

        try {
            Object execute = redisTemplate.execute((RedisCallback<Object>) RedisConnectionCommands::ping);
            Assert.state(execute != null && execute.equals("PONG"), "请配置redis并确保其能够正常连接");
        } catch (Exception e) {
            // skip
        }

        if (timeout == null || timeout.isZero()) {
            properties.setTimeout(Duration.ofSeconds(10));
        }
    }

    private RedisUtils() {
        throw new UnsupportedOperationException();
    }

}

