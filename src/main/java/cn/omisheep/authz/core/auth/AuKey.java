package cn.omisheep.authz.core.auth;

import cn.omisheep.authz.core.util.LogUtils;
import lombok.Data;
import lombok.SneakyThrows;


/**
 * @author zhou xin chen  😊
 * 联系方式 qq:1269670415  email:xinchenzhou666@gmail.com
 */
@Data
public class AuKey {

    private static AuRsa.AuKeyPair auKeyPair;

    private AuKey() {
    }

    @SneakyThrows
    public static void refreshKeyGroup() {
        auKeyPair = AuRsa.genKeyPair();
        LogUtils.logDebug("⬇ auKeyPair ⬇ {} \n", auKeyPair);
    }

    @SneakyThrows
    public static String decrypt(String encryptSource) {
        return AuRsa.decrypt(encryptSource, auKeyPair.getPrivateKey());
    }

    public static String getPublicKeyString() {
        return auKeyPair.getPublicKey();
    }

    public static String getPrivateKeyString() {
        return auKeyPair.getPrivateKey();
    }

}
