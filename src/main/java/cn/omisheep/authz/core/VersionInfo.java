package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.AuthzModifier;
import cn.omisheep.authz.core.msg.VersionMessage;
import cn.omisheep.authz.core.util.MD5Utils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.TaskBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class VersionInfo {

    public static       AtomicInteger            version   = new AtomicInteger(0);
    public static final ArrayList<AuthzModifier> changeLog = new ArrayList<>();
    public static final ArrayList<AuthzModifier> cache     = new ArrayList<>();


    private static String  md5;
    private static boolean md5check    = false;
    private static String  projectPath = null;

    public static String getProjectPath() {
        return projectPath;
    }

    public static void setProjectPath(String projectPath) {
        if (VersionInfo.projectPath == null) VersionInfo.projectPath = projectPath;
    }

    public static boolean isMd5check() {
        return md5check;
    }

    public static void setMd5check(boolean md5check) {
        VersionInfo.md5check = md5check;
    }

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
            VersionInfo.changeLog.add(versionMessage.getAuthzModifier());
        }
    }

    public static Runnable task() {
        return () -> {
            if (loading) {
                TaskBuilder.schedule(task(), "10s");
            } else {
                cache.forEach(VersionInfo::receiveCut);
                cache.clear();
            }
        };
    }

    public static void receiveCut(AuthzModifier authzModifier) {
        AuthzModifier.Operate operate = authzModifier.getOperate();
        if (AuthzModifier.Operate.READ != operate && AuthzModifier.Operate.GET != operate) {
            Authz.op(authzModifier);
        }
    }

    public static void born() {
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(-1, VersionInfo.md5)));
    }

    public static void send(AuthzModifier authzModifier) {
        VersionInfo.changeLog.add(authzModifier);
        int v = VersionInfo.version.incrementAndGet();
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(authzModifier, v, VersionInfo.md5)));
    }

    public static void send() {
        Async.run(() -> RedisUtils.publish(VersionMessage.CHANNEL, new VersionMessage(changeLog, VersionInfo.version.get(), VersionInfo.md5).setTag(true)));
    }
}
