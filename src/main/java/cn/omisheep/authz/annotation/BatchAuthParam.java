package cn.omisheep.authz.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Certificated
public @interface BatchAuthParam {
    AuthParam[] value() default {};
}
