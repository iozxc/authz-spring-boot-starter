package cn.omisheep.authz.annotation;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.2
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Certificated {
}
