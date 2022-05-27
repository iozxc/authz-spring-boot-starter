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

    private RSAConfig rsa = new RSAConfig();

    private IpRangeConfig globalIpRange = new IpRangeConfig();

    private DashboardConfig dashboard = new DashboardConfig();

    private boolean dataFilter = true;

    /**
     * 开启redis缓存时可以不用设置。用户缓存刷新频率，清除掉过期掉值 默认10秒一次，单位 s|m|h|d
     */
    private String userBufferRefreshWithPeriod = "10s";

    /**
     * 定期GC时间，单位 s|m|h|d
     * 为0则关闭
     */
    private String gcPeriod;

    /**
     * authz的日志等级
     */
    private LogLevel log = LogLevel.INFO;

    private boolean md5check = false;

    /**
     * 过滤后缀名
     */
    private String[] ignoreSuffix = new String[]{".css", ".js", ".html", ".png", ".jpg", ".gif", ".svg"};

    @Data
    public static class IpRangeConfig {
        /**
         * 若配置，则必须在这些范围内
         * xx.xx.xx.xx/xx , xx.xx.xx.xx/xx
         */
        private String allow = "";

        /**
         * 拒绝访问网断
         * xx.xx.xx.xx/xx , xx.xx.xx.xx/xx
         */
        private String deny = "";

        /**
         * 0:0:0:0:0:0:0:1  127.0.0.1是否支持
         */
        private boolean supportNative = true;// 0:0:0:0:0:0:0:1  127.0.0.1
    }

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
         * 在读取或者更新之后刷新缓存存活的时间 默认10分钟
         */
        private String expireAfterReadOrUpdateTime = "10m";

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
         * prefix 例如："Bearer <token>"
         */
        private String headerPrefix = "Bearer";

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
    public static class RSAConfig {
        /**
         * 是否开启自动刷新RSA
         */
        private boolean auto = true;

        /**
         * auto为true时生效
         * rsa的key刷新时间，单位 s|m|h|d
         */
        private String rsaKeyRefreshWithPeriod = "7d";

        /**
         * 自定义公钥
         */
        private String customPublicKey;

        /**
         * 自定义私钥
         */
        private String customPrivateKey;
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

    @Data
    public static class DashboardConfig {
        private boolean enabled = false;

        private String username;
        private String password;
        private String allow;
        private String deny;
        private String remoteAddress;

        private String mappings = "/authz-dashboard/*";
    }
}
