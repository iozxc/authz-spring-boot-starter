package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.AuthzManager;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.msg.Message;
import cn.omisheep.authz.core.msg.VersionMessage;
import cn.omisheep.authz.core.util.MD5Utils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.commons.util.Assert;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.TaskBuilder;
import lombok.Data;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.config.Constants.CONNECT_PREFIX;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuthzAppVersion {

    public static final  AtomicInteger            version                            = new AtomicInteger(0);
    public static final  ArrayList<AuthzModifier> changeLog                          = new ArrayList<>();
    public static final  ArrayList<AuthzModifier> cache                              = new ArrayList<>();
    private static final Map<String, String>      _values                            = new HashMap<>();
    public static final  Map<String, String>      values                             = Collections.unmodifiableMap(_values);
    private static       String                   md5;
    private static       boolean                  md5check                           = false;
    private static       String                   projectPath                        = null;
    public static        String                   APPLICATION_NAME;
    public static        String                   APP_NAME;
    private static       boolean                  loading                            = false;
    public static        String                   host;
    public static        String                   port;
    public static        String                   contextPath;
    public static        String                   baseUrl;
    public static        String                   dashboardMappingPrefix;
    public static        boolean                  supportCloud;
    public static        ConnectInfo              connectInfo;
    public static final  String                   CONNECT_INFO_WITH_SAME_APPLICATION = "connectInfoWithSameApplication";
    public static final  String                   CONNECT_INFO_WITH_SAME_APP_NAME    = "connectInfoWithSameAppName";
    public static final  String                   ALL                                = "all";
    public static final  String                   LOCAL                              = "local";

    public static void init(String app) {
        Assert.state(!_values.containsKey("APP"), "APP已初始化");
        _values.put("APP", app);
        _values.put("ACCESS_INFO_KEY_PREFIX", "au:" + app + ":usersAccessInfo:");
        _values.put("REFRESH_INFO_KEY_PREFIX", "au:" + app + ":usersRefreshInfo:");
        _values.put("DEVICE_REQUEST_INFO_KEY_PREFIX", "au:" + app + ":requestInfo:");
        _values.put("PERMISSIONS_BY_ROLE_KEY_PREFIX", "au:" + app + ":permissionsByRole:");
        _values.put("USER_ROLES_KEY_PREFIX", "au:" + app + ":userRoles:");
        _values.put("DASHBOARD_KEY_PREFIX", "au:" + app + ":dashboard:");
    }

    public static String getProjectPath() {
        return projectPath;
    }

    public static void setProjectPath(String projectPath) {
        if (AuthzAppVersion.projectPath == null) AuthzAppVersion.projectPath = projectPath;
    }

    public static boolean isMd5check() {
        return md5check;
    }

    public static void setMd5check(boolean md5check) {
        AuthzAppVersion.md5check = md5check;
        if (md5check) {
            compute();
        }
    }

    public static String getMd5() {
        return md5;
    }

    public static void compute() {
        md5 = MD5Utils.compute(projectPath);
    }

    public static HashMap<String, Object> getVersion() {
        HashMap<String, Object> v = new HashMap<>();
        v.put("version", version + "");
        v.put("appName", APP_NAME);
        v.put("application", APPLICATION_NAME);
        v.put("host", host);
        v.put("port", port);
        v.put("contextPath", contextPath);
        v.put("baseUrl", baseUrl);
        v.put("dashboardMappingPrefix", dashboardMappingPrefix);
        String basePath;
        if (dashboardMappingPrefix.endsWith("/")) {
            basePath = baseUrl + dashboardMappingPrefix + Docs.VERSION;
        } else {
            basePath = baseUrl + dashboardMappingPrefix + "/" + Docs.VERSION;
        }
        v.put("dashboardApiHelper", basePath);
        v.put("dashboardDocs", basePath + "/docs");
        v.put("supportCloud", supportCloud);
        return v;
    }

    @SuppressWarnings("unchecked")
    public static List<ConnectInfo> listAllConnectInfo() {
        Set<String> scan = RedisUtils.scan(CONNECT_PREFIX + "*");
        return RedisUtils.Obj.get(scan);
    }

    public static Map<String, List<ConnectInfo>> getConnectInfo() {
        List<ConnectInfo>                  connectInfo                    = listAllConnectInfo();
        List<ConnectInfo>                  connectInfoWithSameApplication = connectInfo.stream().filter(c -> c.application.equals(APPLICATION_NAME)).collect(Collectors.toList());
        List<ConnectInfo>                  connectInfoWithSameAppName     = connectInfo.stream().filter(c -> c.appName.equals(APP_NAME)).collect(Collectors.toList());
        List<ConnectInfo>                  local                          = connectInfo.stream().filter(c -> c.appName.equals(APP_NAME) && c.application.equals(APPLICATION_NAME)).collect(Collectors.toList());
        HashMap<String, List<ConnectInfo>> map                            = new HashMap<>();
        map.put(CONNECT_INFO_WITH_SAME_APPLICATION, connectInfoWithSameApplication);
        map.put(CONNECT_INFO_WITH_SAME_APP_NAME, connectInfoWithSameAppName);
        map.put(LOCAL, local);
        map.put(ALL, connectInfo);
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
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(-1, AuthzAppVersion.md5)));
        // authz:v1:connect:{MessageId} 30秒后过期  25秒ping一次
        TaskBuilder.schedule(() -> RedisUtils.Obj.set(CONNECT_PREFIX + Message.uuid, connectInfo, 30), 25, TimeUnit.SECONDS);
    }

    public static void send(AuthzModifier authzModifier) {
        AuthzAppVersion.changeLog.add(authzModifier);
        int v = AuthzAppVersion.version.incrementAndGet();
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(authzModifier, v, AuthzAppVersion.md5)));
    }

    public static void send() {
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(changeLog, AuthzAppVersion.version.get(), AuthzAppVersion.md5).setTag(true)));
    }

    @Data
    public static class ConnectInfo {
        private String url;
        private String host;
        private String port;
        private String contextPath;
        private String appName;
        private String application;
    }
}
