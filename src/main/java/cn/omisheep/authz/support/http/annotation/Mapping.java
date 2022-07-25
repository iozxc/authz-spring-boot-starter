package cn.omisheep.authz.support.http.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Mapping {
    String type() default "";

    @AliasFor("value")
    String path() default "";

    @AliasFor("path")
    String value() default "";

    boolean requireLogin() default true;

    String desc() default "";
}
