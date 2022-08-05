package cn.omisheep.authz.core.codec;

import cn.omisheep.authz.annotation.Decrypt;
import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.commons.util.StringUtils;
import com.alibaba.fastjson.JSONObject;

import java.util.Arrays;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.11
 */
public class DecryptHandler {

    private final Class<? extends Decryptor> defaultDecryptor;

    public DecryptHandler(Class<? extends Decryptor> defaultDecryptor) {
        this.defaultDecryptor = defaultDecryptor;
    }

    public String decrypt(String decryptText,
                          Decrypt decrypt) {
        return decrypt(decryptText, decrypt.decryptor());
    }

    public void decryptJSON(JSONObject obj,
                            Decrypt decrypt) {
        for (String field : decrypt.fields()) {
            decryptJSON(field, obj, decrypt.decryptor());
        }
    }

    public String decrypt(String decryptText,
                          Class<? extends Decryptor> decryptorClass) {
        Decryptor decryptor;
        if (RSADecryptor.class != decryptorClass) {
            decryptor = AuthzContext.getBean(decryptorClass);
        } else {
            decryptor = AuthzContext.getBean(defaultDecryptor);
        }
        return decryptor.decrypt(decryptText);
    }

    public void decryptJSON(JSONObject obj,
                            String[] fields,
                            Class<? extends Decryptor> decryptorClass) {
        for (String field : fields) {
            decryptJSON(field, obj, decryptorClass);
        }
    }

    private void decryptJSON(String name,
                             JSONObject obj,
                             Class<? extends Decryptor> decryptorClass) {
        if (!StringUtils.hasText(name)) return;
        String[] trace = Arrays.stream(name.split("\\.")).distinct().toArray(String[]::new);
        decrypt(trace, obj, decryptorClass);
    }

    private void decrypt(String[] trace,
                         JSONObject obj,
                         Class<? extends Decryptor> decryptorClass) {
        if (obj == null) return;

        if (trace.length == 1) {
            if (obj.get(trace[0]) instanceof String) {
                obj.put(trace[0], decrypt(obj.getString(trace[0]), decryptorClass));
            }
        } else {
            if (obj.get(trace[0]) instanceof JSONObject) {
                decrypt(Arrays.copyOfRange(trace, 1, trace.length), obj.getJSONObject(trace[0]), decryptorClass);
            }
        }
    }

}
