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
@Mapping(type = "GET")
public @interface Get {
    @AliasFor(value = "value", annotation = Mapping.class)
    String path() default "";

    @AliasFor(value = "path", annotation = Mapping.class)
    String value() default "";

    @AliasFor(annotation = Mapping.class)
    boolean requireLogin() default true;

    @AliasFor(annotation = Mapping.class)
    String desc() default "";
}
