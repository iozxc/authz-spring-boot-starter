package cn.omisheep.authz.core.tk;

import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.RSAHelper;
import cn.omisheep.commons.util.TaskBuilder;
import lombok.Data;
import lombok.SneakyThrows;

import java.util.concurrent.ScheduledFuture;


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
public class AuKey {

    private static ScheduledFuture<?> scheduledFuture;

    private static boolean auto;

    private static RSAHelper.RSAKeyPair auKeyPair;

    private static String time;


    private AuKey() {
    }

    public static void setTime(String time) {
        AuKey.time = time;
    }

    public static void setAuto(boolean auto) {
        AuKey.auto = auto;
        if (auto) {
            if (scheduledFuture != null) {
                scheduledFuture.cancel(true);
            }
            scheduledFuture = TaskBuilder.schedule(AuKey::refreshKeyGroup, time);
        }
    }

    public static void setAuKeyPair(String publicKey, String privateKey) {
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
            scheduledFuture = null;
        }
        auto      = false;
        auKeyPair = new RSAHelper.RSAKeyPair(publicKey, privateKey);
        LogUtils.logDebug("⬇ auKeyPair ⬇ {} \n", auKeyPair);
    }

    public static void setScheduledFuture(ScheduledFuture<?> scheduledFuture) {
        AuKey.scheduledFuture = scheduledFuture;
    }

    @SneakyThrows
    public static void refreshKeyGroup() {
        auKeyPair = RSAHelper.genKeyPair();
        LogUtils.logDebug("⬇ auKeyPair ⬇ {} \n", auKeyPair);
    }

    @SneakyThrows
    public static String encrypt(String plaintext) {
        return RSAHelper.encrypt(plaintext, auKeyPair.getPublicKey());
    }

    @SneakyThrows
    public static String decrypt(String encryptSource) {
        return RSAHelper.decrypt(encryptSource, auKeyPair.getPrivateKey());
    }

    public static String getPublicKeyString() {
        return auKeyPair.getPublicKey();
    }

    public static String getPrivateKeyString() {
        return auKeyPair.getPrivateKey();
    }

}
