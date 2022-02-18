package cn.omisheep.authz.core.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@SuppressWarnings("all")
@Slf4j
public class RSAUtils {

    private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";//MD5withRSA///RSA/ECB/PKCS1Padding
    /* RSA最大加密明文大小 */
    private static final int MAX_ENCRYPT_BLOCK = 117;
    /* RSA最大解密密文大小 */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /**
     * 使用给定的公钥加密给定的字符串。
     *
     * @param key       给定的公钥。
     * @param plaintext 字符串。
     * @return 给定字符串的密文。
     */
    public static String encryptString(Key key, String plaintext) {
        if (key == null || plaintext == null) {
            return null;
        }
        byte[] data = plaintext.getBytes();
        try {
            byte[] en_data = encrypt(key, data);
            return Base64.encodeBase64String(en_data);
        } catch (Exception ex) {
            log.error("{} Encryption failed. Cause: {}", plaintext, ex.getCause().getMessage());
        }
        return null;
    }

    /**
     * 使用指定的公钥加密数据。
     *
     * @param key  给定的公钥。
     * @param data 要加密的数据。
     * @return 加密后的数据。
     * @throws Exception Exception
     */

    public static byte[] encrypt(Key key, byte[] data) throws Exception {
        Cipher ci = Cipher.getInstance(ALGORITHM);
        ci.init(Cipher.ENCRYPT_MODE, key);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = ci.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = ci.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }


    /**
     * 使用给定的公钥解密给定的字符串。
     *
     * @param key         给定的公钥
     * @param encryptText 密文
     * @return 原文字符串。
     */
    public static String decryptString(Key key, String encryptText) {
        if (key == null || isBlank(encryptText)) {
            return null;
        }
        try {
            byte[] en_data = Base64.decodeBase64(encryptText);
            byte[] data = decrypt(key, en_data);
            return new String(data);
        } catch (Exception ex) {
            log.error("{} Decryption failed. Cause: {}", encryptText, ex.getCause().getMessage());
        }
        return null;
    }

    /**
     * 使用指定的公钥解密数据。
     *
     * @param key  指定的公钥
     * @param data 要解密的数据
     * @return 原数据
     * @throws Exception Exception
     */
    public static byte[] decrypt(Key key, byte[] data) throws Exception {
        Cipher ci = Cipher.getInstance(ALGORITHM);
        ci.init(Cipher.DECRYPT_MODE, key);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = ci.doFinal(data, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = ci.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 判断非空字符串
     *
     * @param cs 待判断的CharSequence序列
     * @return 是否非空
     */
    private static boolean isBlank(final CharSequence cs) {
        int strLen;
        if (cs == null || (strLen = cs.length()) == 0) {
            return true;
        }
        for (int i = 0; i < strLen; i++) {
            if (!Character.isWhitespace(cs.charAt(i))) {
                return false;
            }
        }
        return true;
    }


    public static PublicKey getPublicKey(String key) throws Exception {
        return KeyFactory
                .getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(
                                (new BASE64Decoder()).decodeBuffer(key)
                        )
                );
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        return KeyFactory
                .getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(
                                (new BASE64Decoder()).decodeBuffer(key)
                        )
                );
    }

}