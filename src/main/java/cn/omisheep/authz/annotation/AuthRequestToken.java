package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * 利用参数登录、header登录、cookie登录，没有使用默认逻辑
 *
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthRequestToken {
    @AliasFor("param")
    String value() default "";

    @AliasFor("value")
    String param() default "";

    String header() default "";

    String cookie() default "";
}
