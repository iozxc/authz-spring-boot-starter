package cn.omisheep.authz.core.tk;

import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.RsaHelper;
import lombok.Data;
import lombok.SneakyThrows;


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
public class AuKey {

    private static RsaHelper.RsaKeyPair auKeyPair;

    private AuKey() {
    }

    @SneakyThrows
    public static void refreshKeyGroup() {
        auKeyPair = RsaHelper.genKeyPair();
        LogUtils.logDebug("⬇ auKeyPair ⬇ {} \n", auKeyPair);
    }

    @SneakyThrows
    public static String decrypt(String encryptSource) {
        return RsaHelper.decrypt(encryptSource, auKeyPair.getPrivateKey());
    }

    public static String getPublicKeyString() {
        return auKeyPair.getPublicKey();
    }

    public static String getPrivateKeyString() {
        return auKeyPair.getPrivateKey();
    }

}
