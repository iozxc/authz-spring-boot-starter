package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Auth
@Certificated
public @interface AuthParam {

    @AliasFor(annotation = Auth.class)
    String[] requireRoles() default {};

    @AliasFor(annotation = Auth.class)
    String[] requirePermissions() default {};

    @AliasFor(annotation = Auth.class)
    String[] excludeRoles() default {};

    @AliasFor(annotation = Auth.class)
    String[] excludePermissions() default {};

    /**
     * 作用：限制指定的某个角色或角色组访问的参数内容
     * <p>
     * 优先级低于resources
     *
     * @return scope of access
     */
    String[] range() default {};

    /**
     * 作用：限制某些参数，只有拥有指定的角色或角色组才能访问
     * <p>
     * 优先级高于range
     *
     * @return required protect resources
     */
    String[] resources() default {};

}
