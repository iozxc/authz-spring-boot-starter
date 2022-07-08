package cn.omisheep.authz.annotation;

import cn.omisheep.authz.core.codec.Decryptor;
import cn.omisheep.authz.core.codec.RSADecryptor;
import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * like @Decrypt({"name", "content", "obj.name"})
 * 支持对对象里对某一个属性进行加密解密
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.9
 */
@Target({ElementType.PARAMETER, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Decrypt {

    /**
     * 需要注册在Spring容器中
     *
     * @return 解码器。默认为RSA的解码器，可以在yml里配置默认的解码器
     * @since 1.0.11
     */
    Class<? extends Decryptor> decryptor() default RSADecryptor.class;

    @AliasFor("value")
    String[] fields() default {};

    @AliasFor("fields")
    String[] value() default {};
}
