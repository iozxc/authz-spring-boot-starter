package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Auth
public @interface AuthData {

    @AliasFor(annotation = Auth.class)
    String[] requireRoles() default {};

    @AliasFor(annotation = Auth.class)
    String[] requirePermissions() default {};

    @AliasFor(annotation = Auth.class)
    String[] excludeRoles() default {};

    @AliasFor(annotation = Auth.class)
    String[] excludePermissions() default {};

    String condition() default "";

    Arg[] args() default {};

}
