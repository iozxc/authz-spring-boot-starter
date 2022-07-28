package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.deviced.DeviceCountInfo;
import cn.omisheep.authz.core.codec.Decryptor;
import cn.omisheep.authz.core.codec.RSADecryptor;
import cn.omisheep.authz.support.entity.User;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.logging.LogLevel;

import java.util.ArrayList;
import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@ConfigurationProperties(prefix = "authz")
public class AuthzProperties {

    /**
     * app名，避免在同一redis中启动多Authz服务导致的数据混乱
     *
     * @since 1.1.0
     */
    private String app = "defaultApp";

    /**
     * 是否打印banner
     *
     * @since 1.1.2
     */
    private boolean banner = true;

    /**
     * authz的日志等级
     */
    private LogLevel log = LogLevel.WARN;

    /**
     * 使用`@Decrypt`时的默认的解密器
     *
     * @since 1.0.11
     */
    private Class<? extends Decryptor> defaultDecryptor = RSADecryptor.class;

    /**
     * orm框架 目前仅支持mybatis
     *
     * @since 1.0.5
     */
    private ORM orm;

    /**
     * 过滤后缀名，对dashboard有点用
     */
    private String[] ignoreSuffix = new String[]{".css", ".js", ".html", ".png", ".jpg", ".gif", ".svg"};

    private TokenConfig token = new TokenConfig();

    private UserConfig user = new UserConfig();

    private CacheConfig cache = new CacheConfig();

    private RSAConfig rsa = new RSAConfig();

    private IpRangeConfig globalIpRange = new IpRangeConfig();

    private DashboardConfig dashboard = new DashboardConfig();
    /**
     * @since 1.1.3
     */
    private ResponseConfig  response  = new ResponseConfig();

    private OtherConfig sys = new OtherConfig();

    @Data
    public static class TokenConfig {

        /**
         * 签名的私钥，若长度不够将自动填充，若为空，将不执行数字签名
         */
        private String key;

        /**
         * oauth配置
         *
         * @since 1.2.0
         */
        private OpenAuthConfig oauth = new OpenAuthConfig();

        /**
         * Token字符串表示模式。默认为标准模式。
         */
        private Mode mode = Mode.STANDARD;

        /**
         * Token签名算法
         */
        private SignatureAlgorithm algorithm = SignatureAlgorithm.HS256;

        /**
         * Token压缩算法
         */
        private Compress compress = Compress.NONE;

        /**
         * tokenId的长度
         */
        private int tokenIdBits = 8;

        /**
         * cookie name
         */
        private String cookieName = "atkn";

        /**
         * header name
         */
        private String headerName = "Authorization";

        /**
         * prefix 例如：headerPrefix = 'Bearer' -> "Bearer <token>"
         * headerPrefix不需要在最后空格，但是在请求时需要空一格
         */
        private String headerPrefix = "Bearer";

        /**
         * access token有效时间，默认 7d ，单位 ms|s|m|h|d
         */
        private String accessTime = "7d";

        /**
         * refresh token有效时间，默认 30d ，单位 ms|s|m|h|d
         */
        private String refreshTime = "30d";

        /**
         * issuer 发行用户
         */
        private String issuer;

        public enum Mode {
            STANDARD,
            BRIEF,
            OLD
        }

        public enum Compress {
            GZIP,
            DEFLATE,
            NONE
        }

        @Data
        public static class OpenAuthConfig {

            /**
             * 授权码过期时间
             */
            private String authorizationCodeTime = "10m";

            /**
             * 默认授予的权限。
             * 通过oauth授权登录的用户拥有的权限，`@OAuthScopeBasic`标识之后的额外scope
             * 通过正常登录的用户不受scope的影响，能访问所有资源
             */
            private String defaultScope = "basic";

            /**
             * 客户端Id长度 默认24
             */
            private int clientIdLength = 24;

            /**
             * 客户端密钥长度 默认30位
             */
            private int clientSecretLength = 30;

            /**
             * 授权码签名算法
             */
            private AuthorizationCodeAlgorithm algorithm = AuthorizationCodeAlgorithm.SHA1;

            public enum AuthorizationCodeAlgorithm {
                SHA_256("SHA-256"), SHA1("SHA1"), MD5("MD5");

                private final String value;

                AuthorizationCodeAlgorithm(String value) {
                    this.value = value;
                }

                public String getValue() {
                    return value;
                }
            }
        }

    }


    @Data
    public static class UserConfig {

        /**
         * 登录设备总数默不做限制【-1为不做限制，最小为1】，超出会挤出最长时间未访问的设备。
         */
        private int maximumTotalDevice = -1;

        public int getMaximumTotalDevice() {
            if (maximumTotalDevice == 0) return 1;
            if (maximumTotalDevice < 0) return -1;
            return maximumTotalDevice;
        }

        /**
         * 同类型设备最大登录数 默认 1个【-1为不做限制，最小为1】，超出会挤出最长时间未访问的设备。
         */
        private int maximumSameTypeDeviceCount = 1;

        public int getMaximumSameTypeDeviceCount() {
            if (maximumSameTypeDeviceCount == 0) return 1;
            if (maximumSameTypeDeviceCount < 0) return -1;
            return maximumSameTypeDeviceCount;
        }

        /**
         * 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1），超出会挤出最长时间未访问的设备。
         */
        private List<DeviceCountInfo> typesTotal = new ArrayList<>();

    }

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

    public enum ORM {
        MYBATIS
    }

    @Data
    public static class DashboardConfig {
        /**
         * 是否开启dashboard
         */
        private boolean    enabled = false;
        /**
         * 登录用户，可与username，password共用
         */
        private List<User> users   = new ArrayList<>();
        /**
         * 用户名
         */
        private String     username;
        /**
         * 用户密码
         */
        private String     password;
        /**
         * 【-只only-允许】的iprange
         */
        private String     allow;
        /**
         * 拒绝的iprange
         */
        private String     deny;
    }

    @Data
    public static class ResponseConfig {
        /**
         * 返回体状态码是否永远为200、不论是否出错（默认状态下）
         */
        private boolean alwaysOk = false;
    }

    @Data
    public static class OtherConfig{

        /**
         * 定期GC时间，单位 s|m|h|d
         * 为0或为空则关闭
         */
        private String gcPeriod;

        /**
         * 没啥用，可能以后会有用
         */
        private boolean md5check = false;

    }
}
