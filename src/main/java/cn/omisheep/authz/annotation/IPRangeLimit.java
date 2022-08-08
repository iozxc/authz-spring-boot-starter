package cn.omisheep.authz.annotation;

import java.lang.annotation.*;

/**
 * {@link cn.omisheep.authz.support.util.IPRange}
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface IPRangeLimit {

    /**
     * @return xx.xx.xx.xx/xx , xx.xx.xx.xx/xx
     */
    String allow() default "";

    /**
     * @return xx.xx.xx.xx/xx , xx.xx.xx.xx/xx
     */
    String deny() default "";

}
