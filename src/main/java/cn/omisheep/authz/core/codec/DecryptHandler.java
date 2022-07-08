package cn.omisheep.authz.core.codec;

import cn.omisheep.authz.annotation.Decrypt;
import cn.omisheep.authz.core.util.AUtils;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.11
 */
public class DecryptHandler {

    private final Class<? extends Decryptor> defaultDecryptor;

    public DecryptHandler(Class<? extends Decryptor> defaultDecryptor) {
        this.defaultDecryptor = defaultDecryptor;
    }

    public String decrypt(String decryptText, Decrypt decrypt) {
        Decryptor decryptor;
        if (RSADecryptor.class != decrypt.decryptor()) {
            decryptor = AUtils.getBean(decrypt.decryptor());
        } else {
            decryptor = AUtils.getBean(defaultDecryptor);
        }
        return decryptor.decrypt(decryptText);
    }
}
