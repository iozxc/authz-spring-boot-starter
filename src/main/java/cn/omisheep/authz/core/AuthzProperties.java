package cn.omisheep.authz.core;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.logging.LogLevel;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@ConfigurationProperties(prefix = "authz")
public class AuthzProperties {

    private TokenConfig token = new TokenConfig();

    private UserConfig user = new UserConfig();

    private CacheConfig cache = new CacheConfig();

    private MybatisConfig mybatis = new MybatisConfig();

    private boolean dataFilter = true;

//    /**
//     * role/permission分隔符
//     * <p>
//     * role :  "zxc,user"
//     * <p>
//     * permission :   "user:create,user:update"
//     */
//    private String permSeparator = ",";

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
         * 是否开启redis健康监控检查，默认关闭
         */
        private boolean enableRedisActuator = false;

        /**
         * redis每次扫描key的数量
         */
        private int redisScanCount = 10000;

        /**
         * 最大缓存数，不配置时默认无大小限制
         */
        private Long cacheMaximumSize;

        /**
         * 在读取或者更新之后刷新缓存存活的时间 默认1分钟
         */
        private String expireAfterReadOrUpdateTime = "1m";

    }

    @Data
    public static class TokenConfig {

        /**
         * 签名的私钥
         */
        private String key;

        /**
         * cookie name
         */
        private String cookieName = "atkn";

        /**
         * header name
         */
        private String headerName = "Authorization";

        /**
         * 头模版
         */
        private String headerTemplate = "Bearer <token>";

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

    @Data
    public static class MybatisConfig {

        private Version version = Version.V_3_4_0_up;

        enum Version {
            V_3_4_0_up("3.4.0+"),
            V_3_4_0_low("3.4.0-");

            Version(String version) {
                this.version = version;
            }

            private final String version;

            public String getVersion() {
                return version;
            }
        }
    }
}
