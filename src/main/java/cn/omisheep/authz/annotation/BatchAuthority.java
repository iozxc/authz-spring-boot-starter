package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BatchAuthority {

    @AliasFor("roles")
    Roles[] value() default {};

    @AliasFor("value")
    Roles[] roles() default {};

    Perms[] perms() default {};

}
