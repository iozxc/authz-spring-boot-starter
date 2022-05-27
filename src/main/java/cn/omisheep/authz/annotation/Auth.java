package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.2
 */
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Certificated
public @interface Auth {

    AuthScope scope();

    @AliasFor("require")
    String[] value() default {};

    @AliasFor("value")
    String[] require() default {};

    String[] exclude() default {};

    /**
     * 作用：限制指定的某个角色或角色组访问的参数内容
     * <p>
     * 优先级低于paramResources
     *
     * @return scope of access
     */
    String[] paramRange() default {};

    /**
     * 作用：限制某些参数，只有拥有指定的角色或角色组才能访问
     * <p>
     * 优先级高于paramRange
     *
     * @return required protect resources
     */
    String[] paramResources() default {};

    String condition() default "";

    Arg[] args() default {};

}
