package cn.omisheep.authz.core.slot;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Order {
    @AliasFor("order")
    int value() default Integer.MAX_VALUE;

    @AliasFor("value")
    int order() default Integer.MAX_VALUE;
}
