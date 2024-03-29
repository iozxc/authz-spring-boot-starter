package cn.omisheep.authz.support.http.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Param {
    @AliasFor("value")
    String name() default "";

    @AliasFor("name")
    String value() default "";
}
