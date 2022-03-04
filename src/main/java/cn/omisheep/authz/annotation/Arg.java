package cn.omisheep.authz.annotation;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({})
public @interface Arg {
    String resource();

    String[] args() default "";
}
