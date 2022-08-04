package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.AuthzManager;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.msg.*;
import cn.omisheep.authz.core.util.MD5Utils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.authz.core.util.Utils;
import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.commons.util.Assert;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.TaskBuilder;
import cn.omisheep.commons.util.TimeUtils;
import lombok.Data;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.springframework.boot.system.ApplicationHome;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.util.StringUtils;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.config.Constants.CONNECT_PREFIX;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuthzAppVersion {

    private static       boolean                  loading      = false;
    public static final  AtomicInteger            version      = new AtomicInteger(0);
    public static final  ArrayList<AuthzModifier> changeLog    = new ArrayList<>();
    public static final  ArrayList<AuthzModifier> cache        = new ArrayList<>();
    private static final Map<String, String>      _values      = new HashMap<>();
    private static final Map<String, Object>      _values_obj  = new HashMap<>();
    public static final  Map<String, String>      values       = Collections.unmodifiableMap(_values);
    public static final  Map<String, Object>      valuesObject = Collections.unmodifiableMap(_values_obj);

    public static final  String  srcFolder = new File(
            Objects.requireNonNull(AuthzVersion.class.getClassLoader().getResource("")).getPath()).toString();
    private static final String  osName    = System.getProperty("os.name").toLowerCase();
    public static final  boolean isMac     = osName.contains("mac");
    public static final  boolean isWindows = osName.contains("window");
    public static final  boolean isLinux   = osName.contains("linux");

    public static final String CONNECT_INFO_WITH_SAME_APPLICATION = "connectInfoWithSameApplication";
    public static final String CONNECT_INFO_WITH_SAME_APP_NAME    = "connectInfoWithSameAppName";
    public static final String ALL_CONNECT                        = "all";
    public static final String LOCAL_CONNECT                      = "local";

    public static Class<?>                mainClass = AuthzAppVersion.class;
    public static ConfigurableEnvironment environment;
    public static AuthzProperties         properties;

    private static final Supplier<Boolean> md5check = () -> properties.getSys().isMd5check();

    public static final Supplier<String> HOST = () -> _values.computeIfAbsent("HOST", r -> {
        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            return "unknown";
        }
    });

    public static Supplier<String> PORT = () -> _values.computeIfAbsent("PORT", r -> Optional.ofNullable(
            environment.getProperty("server.port")).orElse("unknown"));

    public static Supplier<String> CONTEXT_PATH
            = () -> _values.computeIfAbsent("CONTEXT_PATH",
                                            r -> Optional.ofNullable(
                                                            environment.getProperty(
                                                                    "server.servlet.context-path"))
                                                    .orElse(""));

    public static Supplier<String> BASE_URL
            = () -> _values.computeIfAbsent("BASE_URL",
                                            r -> Utils.format("{}:{}{}", HOST.get(),
                                                              PORT.get(),
                                                              CONTEXT_PATH.get()));

    public static final Supplier<Boolean> SUPPORT_REDIS = () -> properties.getCache().isEnableRedis();

    public static final Supplier<String> APPLICATION_NAME = () -> _values.computeIfAbsent("APPLICATION_NAME", r -> {
        String name = environment.getProperty("spring.application.name");
        return StringUtils.hasText(name) ? name : "application";
    });

    public static final Supplier<String> APP_NAME = () -> properties.getApp();

    public static final Supplier<ConnectInfo> CONNECT_INFO = () -> (ConnectInfo) _values_obj.computeIfAbsent(
            "CONNECT_INFO", r -> {
                ConnectInfo connectInfo = new ConnectInfo();
                connectInfo.setApplication(APPLICATION_NAME.get());
                connectInfo.setAppName(APP_NAME.get());
                connectInfo.setContextPath(CONTEXT_PATH.get());
                connectInfo.setUrl(Utils.format("{}:{}", HOST.get(), HOST.get()));
                connectInfo.setHost(HOST.get());
                connectInfo.setPort(PORT.get());
                if (properties.getDashboard().isEnabled()) {
                    String u = BASE_URL.get();
                    if (!BASE_URL.get().endsWith("/")) {u = u + "/";}
                    connectInfo.setDashboard(u + "authz.html");
                }
                return connectInfo;
            });

    public static final Supplier<Long> AUTHORIZATION_CODE_TIME = () -> (Long) _values_obj.computeIfAbsent(
            "AUTHORIZATION_CODE_TIME", r -> TimeUtils.parseTimeValue(properties.getOauth().getAuthorizationCodeTime()));

    public static final Supplier<String> SCOPE_SEPARATOR = () -> properties.getOauth().getScopeSeparator();

    private static final Supplier<String> JAR_PATH = () -> {
        try {
            return _values.computeIfAbsent("JAR_PATH",
                                           r -> new ApplicationHome(mainClass).getSource().getAbsolutePath());
        } catch (Exception e) {
            return _values.computeIfAbsent("JAR_PATH", r -> "unknown");
        }
    };

    private static final Supplier<String> JAR_MD5 = () -> {
        try {
            return _values.computeIfAbsent("JAR_MD5", r -> MD5Utils.compute(JAR_PATH.get()));
        } catch (Exception e) {
            return _values.computeIfAbsent("JAR_MD5", r -> "unknown");
        }
    };

    public static final Supplier<Void> init = () -> {
        Assert.state(!_values.containsKey("APP"), "APP已初始化");

        _values.put("APP", APP_NAME.get());

        _values.put("USER_DEVICE_KEY_PREFIX", "authz:" + APP_NAME.get() + ":user:device:");
        _values.put("USER_REQUEST_KEY_PREFIX", "authz:" + APP_NAME.get() + ":user:request");

        _values.put("OAUTH_USER_DEVICE_KEY_PREFIX", "authz:" + APP_NAME.get() + ":oauth:user:device:");

        _values.put("ACCESS_INFO_KEY_PREFIX", "authz:" + APP_NAME.get() + ":usersAccessInfo:");
        _values.put("REFRESH_INFO_KEY_PREFIX", "authz:" + APP_NAME.get() + ":usersRefreshInfo:");

        _values.put("PERMISSIONS_BY_ROLE_KEY_PREFIX", "authz:" + APP_NAME.get() + ":permissionsByRole:");
        _values.put("ROLES_BY_USER_KEY_PREFIX", "authz:" + APP_NAME.get() + ":userRoles:");

        _values.put("CLINT_PREFIX", "authz:" + APP_NAME.get() + ":oauth:client:");
        _values.put("AUTHORIZE_CODE_PREFIX", "authz:" + APP_NAME.get() + ":oauth:code:");

        _values.put("DASHBOARD_KEY_PREFIX", "authz:" + APP_NAME.get() + ":dashboard:");

        return null;
    };

    @Data
    public static class ConnectInfo {
        private String url;
        private String host;
        private String port;
        private String contextPath;
        private String appName;
        private String application;
        private String dashboard;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;

            if (!(o instanceof ConnectInfo)) return false;

            ConnectInfo that = (ConnectInfo) o;

            return new EqualsBuilder().append(getUrl(), that.getUrl())
                    .append(getHost(), that.getHost())
                    .append(getPort(), that.getPort())
                    .isEquals();
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(17, 37).append(getUrl()).append(getHost()).append(getPort()).toHashCode();
        }
    }

    public static boolean isMd5check() {
        return md5check.get();
    }

    public static String getJarMd5() {
        return JAR_MD5.get();
    }

    public static String getJarPath() {
        return JAR_PATH.get();
    }

    @SuppressWarnings("unchecked")
    public static HashMap<String, Object> getVersion() {
        return (HashMap<String, Object>) _values_obj.computeIfAbsent("CONNECT_VERSION", r -> {
            HashMap<String, Object> v = new HashMap<>();
            v.put("version", version.get() + "");
            v.put("appName", APP_NAME.get());
            v.put("application", APPLICATION_NAME.get());
            v.put("host", HOST.get());
            v.put("port", PORT.get());
            v.put("contextPath", CONTEXT_PATH.get());
            v.put("baseUrl", BASE_URL.get());
            v.put("dashboardApiHelper", BASE_URL.get() + Constants.DASHBOARD_API_PREFIX + Docs.VERSION_PATH);
            v.put("dashboardDocs", BASE_URL.get() + Constants.DASHBOARD_API_PREFIX + Docs.VERSION_PATH + "/docs");
            v.put("supportCloud", SUPPORT_REDIS.get());
            v.put("os", osName);
            v.put("srcFolder", srcFolder);
            return v;
        });
    }

    @SuppressWarnings("unchecked")
    public static List<ConnectInfo> listAllConnectInfo() {
        Set<String> scan = RedisUtils.scan(CONNECT_PREFIX + "*");
        return RedisUtils.Obj.get(scan);
    }

    public static Map<String, List<ConnectInfo>> getConnectInfo() {
        List<ConnectInfo> connectInfo = listAllConnectInfo().stream().distinct().collect(Collectors.toList());
        List<ConnectInfo> connectInfoWithSameApplication = connectInfo.stream()
                .filter(c -> c.application.equals(APPLICATION_NAME.get()))
                .collect(Collectors.toList());
        List<ConnectInfo> connectInfoWithSameAppName = connectInfo.stream()
                .filter(c -> c.appName.equals(APP_NAME.get()))
                .collect(Collectors.toList());
        List<ConnectInfo> local = connectInfo.stream()
                .filter(c -> c.appName.equals(APP_NAME.get()) && c.application.equals(APPLICATION_NAME.get()))
                .collect(Collectors.toList());
        HashMap<String, List<ConnectInfo>> map = new HashMap<>();
        map.put(CONNECT_INFO_WITH_SAME_APPLICATION, connectInfoWithSameApplication);
        map.put(CONNECT_INFO_WITH_SAME_APP_NAME, connectInfoWithSameAppName);
        map.put(LOCAL_CONNECT, local);
        map.put(ALL_CONNECT, connectInfo);
        return map;
    }

    public static void receive(VersionMessage versionMessage) {
        if (versionMessage.isTag()) {
            if (version.get() == 0) {
                List<AuthzModifier> authzModifierList = versionMessage.getAuthzModifierList();
                if (authzModifierList != null && versionMessage.getVersion() == authzModifierList.size()) {
                    loading = true;
                    for (AuthzModifier modifier : authzModifierList) {
                        receiveCut(modifier);
                        version.incrementAndGet();
                    }
                    loading = false;
                }
            }
            return;
        }

        if (versionMessage.getVersion() == -1 && !loading) {
            send();
            return;
        }

        AuthzModifier authzModifier = versionMessage.getAuthzModifier();

        if (authzModifier != null) {
            if (loading) {
                cache.add(authzModifier);
                TaskBuilder.scheduleOnceDelay(task(), "10s");
                return;
            }
            receiveCut(authzModifier);
            version.incrementAndGet();
            AuthzAppVersion.changeLog.add(versionMessage.getAuthzModifier());
        }
    }

    public static Runnable task() {
        return () -> {
            if (loading) {
                TaskBuilder.scheduleOnceDelay(task(), "10s");
            } else {
                cache.forEach(AuthzAppVersion::receiveCut);
                cache.clear();
            }
        };
    }

    public static void receiveCut(AuthzModifier authzModifier) {
        AuthzModifier.Operate operate = authzModifier.getOperate();
        if (AuthzModifier.Operate.READ != operate && AuthzModifier.Operate.GET != operate) {
            AuthzManager.op(authzModifier);
        }
    }

    public static void born() {
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL,
                                           new VersionMessage(-1, AuthzAppVersion.JAR_MD5.get())));
        // authz:v1:connect:{MessageId} 30秒后过期  25秒一次
        TaskBuilder.schedule(AuthzAppVersion::ping, 25, TimeUnit.SECONDS);
    }

    public static void ping() {
        try {
            RedisUtils.Obj.set(CONNECT_PREFIX + Message.uuid, CONNECT_INFO.get(), 30);
        } catch (Exception e) {
            // skip
        }
    }

    public static void send(AuthzModifier authzModifier) {
        AuthzAppVersion.changeLog.add(authzModifier);
        int v = AuthzAppVersion.version.incrementAndGet();
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL,
                                           new VersionMessage(authzModifier, v, AuthzAppVersion.JAR_MD5.get())));
    }

    public static void send() {
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL,
                                           new VersionMessage(changeLog, AuthzAppVersion.version.get(),
                                                              AuthzAppVersion.JAR_MD5.get()).setTag(true)));
    }

}
