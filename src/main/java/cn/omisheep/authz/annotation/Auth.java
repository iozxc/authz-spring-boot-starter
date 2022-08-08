package cn.omisheep.authz.annotation;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Certificated
public @interface Auth {
    String[] requireRoles() default {};

    String[] requirePermissions() default {};

    String[] excludeRoles() default {};

    String[] excludePermissions() default {};
}
