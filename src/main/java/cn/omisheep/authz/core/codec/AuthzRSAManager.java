package cn.omisheep.authz.core.codec;

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
public class AuthzRSAManager {

    private static ScheduledFuture<?> scheduledFuture;

    private static boolean auto;

    private static RSAHelper.RSAKeyPair auKeyPair;

    private static String time;

    private AuthzRSAManager() {
    }

    public static void setTime(String time) {
        AuthzRSAManager.time = time;
    }

    public static void setAuto(boolean auto) {
        AuthzRSAManager.auto = auto;
        if (auto) {
            if (scheduledFuture != null) {
                scheduledFuture.cancel(true);
            }
            scheduledFuture = TaskBuilder.schedule(AuthzRSAManager::refreshKeyGroup, time);
        }
    }

    public static void setAuKeyPair(String publicKey,
                                    String privateKey) {
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
            scheduledFuture = null;
        }
        auto      = false;
        auKeyPair = new RSAHelper.RSAKeyPair(publicKey, privateKey);
        LogUtils.debug("⬇ RSA Key Pair ⬇ {} \n", auKeyPair);
    }

    @SneakyThrows
    public static void refreshKeyGroup() {
        auKeyPair = RSAHelper.genKeyPair();
        LogUtils.debug("⬇ RSA Key Pair ⬇ {} \n", auKeyPair);
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
