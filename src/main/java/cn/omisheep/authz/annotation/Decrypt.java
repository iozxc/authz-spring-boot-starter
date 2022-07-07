package cn.omisheep.authz.annotation;

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
    @AliasFor("value")
    String[] fields() default {};

    @AliasFor("fields")
    String[] value() default {};
}
