package cn.omisheep.authz.core.codec;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.11
 */
public class RSADecryptor implements Decryptor {

    @Override
    public String decrypt(String encryptText) {
        return AuKey.decrypt(encryptText);
    }
}
