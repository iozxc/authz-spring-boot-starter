package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhou xin chen
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Roles {

    /**
     * 所需要的角色 可以 写在一个字符串中用分隔符隔开，或者分开写
     *
     * @return -
     */
    @AliasFor("require")
    String[] value() default {};

    /**
     * 所需要的角色 可以 写在一个字符串中用分隔符隔开，或者分开写
     *
     * @return -
     */
    @AliasFor("value")
    String[] require() default {};

    /**
     * 所排除的权限，优先级大于value
     *
     * @return -
     */
    String[] exclude() default {};
}
