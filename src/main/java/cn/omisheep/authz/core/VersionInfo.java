package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.AuthzModifier;
import cn.omisheep.authz.core.msg.VersionMessage;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.TaskBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class VersionInfo {

    public static       AtomicInteger            version   = new AtomicInteger(0);
    public static final ArrayList<AuthzModifier> changeLog = new ArrayList<>();
    public static final ArrayList<AuthzModifier> cache     = new ArrayList<>();

    public static final String  md5     = ""; // jar包计算
    public static       String  APP_NAME;
    private static      boolean loading = false;

    public static String host;
    public static String port;
    public static String path;
    public static String prefix;

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