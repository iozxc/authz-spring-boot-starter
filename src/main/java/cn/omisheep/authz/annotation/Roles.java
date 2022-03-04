package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Roles {

    @AliasFor("require")
    String[] value() default {};

    @AliasFor("value")
    String[] require() default {};

    String[] exclude() default {};

    String[] resources() default {};

    String condition() default "";

    Arg[] conditionArgs() default {};

}
