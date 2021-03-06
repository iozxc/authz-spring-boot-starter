package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.AuthzFactory;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.msg.VersionMessage;
import cn.omisheep.authz.core.util.MD5Utils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Assert;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.TaskBuilder;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuthzAppVersion {

    public static final AtomicInteger            version   = new AtomicInteger(0);
    public static final ArrayList<AuthzModifier> changeLog = new ArrayList<>();
    public static final ArrayList<AuthzModifier> cache     = new ArrayList<>();

    private static final Map<String, String> _values = new HashMap<>();
    public static final  Map<String, String> values  = Collections.unmodifiableMap(_values);

    public static void init(String app) {
        Assert.state(!_values.containsKey("APP"), "APP已初始化");
        _values.put("APP", app);
        _values.put("ACCESS_INFO_KEY_PREFIX", "au:" + app + ":usersAccessInfo:");
        _values.put("REFRESH_INFO_KEY_PREFIX", "au:" + app + ":usersRefreshInfo:");
        _values.put("DEVICE_REQUEST_INFO_KEY_PREFIX", "au:" + app + ":requestInfo:");
        _values.put("PERMISSIONS_BY_ROLE_KEY_PREFIX", "au:" + app + ":permissionsByRole:");
        _values.put("USER_ROLES_KEY_PREFIX", "au:" + app + ":userRoles:");
    }

    private static String  md5;
    private static boolean md5check    = false;
    private static String  projectPath = null;

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

    public static  String  APPLICATION_NAME;
    public static  String  APP_NAME;
    private static boolean loading = false;

    public static String host;
    public static String port;
    public static String path;
    public static String prefix;

    public static String getMd5() {
        return md5;
    }

    public static void compute() {
        md5 = MD5Utils.compute(projectPath);
    }

    public static HashMap<String, String> getVersion() {
        HashMap<String, String> v = new HashMap<>();
        v.put("version", version + "");
        v.put("name", APP_NAME);
        v.put("application", APPLICATION_NAME);
        v.put("host", host);
        v.put("port", port);
        v.put("path", path);
        v.put("prefix", prefix);
        return v;
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
                TaskBuilder.schedule(task(), "10s");
            } else {
                cache.forEach(AuthzAppVersion::receiveCut);
                cache.clear();
            }
        };
    }

    public static void receiveCut(AuthzModifier authzModifier) {
        AuthzModifier.Operate operate = authzModifier.getOperate();
        if (AuthzModifier.Operate.READ != operate && AuthzModifier.Operate.GET != operate) {
            AuthzFactory.op(authzModifier);
        }
    }

    public static void born() {
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(-1, AuthzAppVersion.md5)));
    }

    public static void send(AuthzModifier authzModifier) {
        AuthzAppVersion.changeLog.add(authzModifier);
        int v = AuthzAppVersion.version.incrementAndGet();
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(authzModifier, v, AuthzAppVersion.md5)));
    }

    public static void send() {
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(changeLog, AuthzAppVersion.version.get(), AuthzAppVersion.md5).setTag(true)));
    }
}
