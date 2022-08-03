package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Auth
public @interface AuthField {

    @AliasFor(annotation = Auth.class)
    String[] requireRoles() default {};

    @AliasFor(annotation = Auth.class)
    String[] requirePermissions() default {};

    @AliasFor(annotation = Auth.class)
    String[] excludeRoles() default {};

    @AliasFor(annotation = Auth.class)
    String[] excludePermissions() default {};

}
