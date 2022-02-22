package cn.omisheep.authz.core.auth;


import cn.omisheep.commons.util.RSAUtils;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Slf4j
public class AuRsa {

    @Data
    @AllArgsConstructor
    public static class AuKeyPair {
        private String publicKey;
        private String privateKey;

        @Override
        public String toString() {
            return "\npublicKey=\n" + publicKey +
                    "\nprivateKey=\n" + privateKey;
        }
    }


    /**
     * 随机生成密钥对
     *
     * @return AuKeyPair密钥对
     * @throws NoSuchAlgorithmException e
     */
    public static AuKeyPair genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();

        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
        String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));

        return new AuKeyPair(publicKeyString, privateKeyString);
    }


    /**
     * RSA公钥加密
     *
     * @param str       明文
     * @param publicKey 公钥
     * @return 加密字符串
     */
    @SneakyThrows
    public static String encrypt(String str, String publicKey) {
        return RSAUtils.encryptString(RSAUtils.getPublicKey(publicKey), str);
    }


    /**
     * RSA私钥解密
     *
     * @param str        秘文
     * @param privateKey 私钥
     * @return 明文
     */
    @SneakyThrows
    public static String decrypt(String str, String privateKey) {
        return RSAUtils.decryptString(RSAUtils.getPrivateKey(privateKey), bugfix(str));
    }


    public static String bugfix(String text) {
        return text.replaceAll(" ", "+");
    }

}