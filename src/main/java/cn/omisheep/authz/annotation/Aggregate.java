package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Aggregate {

    @AliasFor("statisticalType")
    StatisticalType[] value() default {};

    @AliasFor("value")
    StatisticalType[] statisticalType() default {};

    String refer() default "";

    /**
     * 统计的作用域，默认为全局
     *
     * @return -
     */
    String scope() default "";
}
