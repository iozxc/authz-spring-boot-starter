package cn.omisheep.authz.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * name全局唯一
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface ArgResource {

    /**
     * 不写默认为方法名，同名会被覆盖
     *
     * @return 全局唯一
     */
    @AliasFor("name")
    String value() default "";

    /**
     * 不写默认为方法名，同名会被覆盖
     *
     * @return 全局唯一
     */
    @AliasFor("value")
    String name() default "";

    /**
     * @return 描述
     */
    String description() default "";

}
