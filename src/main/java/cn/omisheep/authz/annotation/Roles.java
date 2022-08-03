package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Certificated
@Auth
public @interface Roles {

    @AliasFor(value = "requireRoles", annotation = Auth.class)
    String[] value() default {};

    @AliasFor(value = "requireRoles", annotation = Auth.class)
    String[] require() default {};

    @AliasFor(value = "excludeRoles", annotation = Auth.class)
    String[] exclude() default {};

}
