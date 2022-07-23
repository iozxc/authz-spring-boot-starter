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
@Mapping(type = "POST")
public @interface Post {
    @AliasFor("value")
    String path() default "";

    @AliasFor("path")
    String value() default "";

    @AliasFor(annotation = Mapping.class)
    boolean requireLogin() default true;
}
