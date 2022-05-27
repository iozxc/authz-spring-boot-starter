package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Auth(scope = AuthScope.ROLE)
public @interface Perms {

    @AliasFor(value = "require", annotation = Auth.class)
    String[] value() default {};

    @AliasFor(value = "value", annotation = Auth.class)
    String[] require() default {};

    @AliasFor(annotation = Auth.class)
    String[] exclude() default {};

    /**
     * 作用：限制指定的某个角色或角色组访问的参数内容
     * <p>
     * 优先级低于paramResources
     *
     * @return scope of access
     */
    @AliasFor(annotation = Auth.class)
    String[] paramRange() default {};

    /**
     * 作用：限制某些参数，只有拥有指定的角色或角色组才能访问
     * <p>
     * 优先级高于paramRange
     *
     * @return required protect resources
     */
    @AliasFor(annotation = Auth.class)
    String[] paramResources() default {};

    @AliasFor(annotation = Auth.class)
    String condition() default "";

    @AliasFor(annotation = Auth.class)
    Arg[] args() default {};
}
