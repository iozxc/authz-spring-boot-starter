package cn.omisheep.authz.core;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.logging.LogLevel;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Data
@ConfigurationProperties(
        prefix = "authz"
)
public class AuthzProperties {

    private TokenConfig token = new TokenConfig();

    private UserConfig user = new UserConfig();

    private CacheConfig cache = new CacheConfig();

    private boolean enableCatchException = false;

    /**
     * role/permission分隔符
     * <p>
     * role :  "zxc,user"
     * <p>
     * permission :   "user:create,user:update"
     */
    private String permSeparator = ",";

    /**
     * cookie name
     */
    private String cookieName = "atkn";

    /**
     * header name
     */
    private String headerName = "Authorization";

    /**
     * rsa的key刷新时间，单位 s|m|h|d
     */
    private String rsaKeyRefreshWithPeriod = "7d";

    /**
     * 开启redis缓存时可以不用设置。用户缓存刷新频率，清除掉过期掉值 默认10秒一次，单位 s|m|h|d
     */
    private String userBufferRefreshWithPeriod = "10s";

    /**
     * 定期GC时间，单位 s|m|h|d
     * 为0则关闭
     */
    private String gcPeriod;

    private LogLevel log = LogLevel.INFO;

    @Data
    public static class CacheConfig {

        /**
         * 是否开启redis缓存（两级缓存）
         * L2
         */
        private boolean enableRedis = false;

        /**
         * redis每次扫描key的数量
         */
        private int redisScanCount = 10000;

        /**
         * 最大缓存数，不配置时默认无大小限制
         */
        private Long cacheMaximumSize;

        /**
         * 在读取或者更新之后刷新缓存存活的时间
         */
        private String expireAfterReadOrUpdateTime = "10s";

    }

    @Data
    public static class TokenConfig {

        /**
         * 签名的私钥
         */
        private String key;

        /**
         * 存活时间，默认 7d ，单位 ms|s|m|h|d
         */
        private String liveTime = "7d";

        /**
         * 刷新时间，默认 30d ，单位 ms|s|m|h|d
         */
        private String refreshTime = "30d";

        /**
         * issuer
         */
        private String issuer = "au";

    }

    /**
     * 全局默认配置，当全部配置时生效，默认作用于所有路由，优先级最低，会被其他AuLimit和Au覆盖
     */
    @Data
    public static class UserConfig {

        /**
         * 是否支持多设备登录(type不同，id不同)
         */
        private boolean supportMultiDevice = true;

        /**
         * 是否支持同类型设备多登录（type相同，id不同）
         */
        private boolean supportMultiUserForSameDeviceType = false;

    }

}
