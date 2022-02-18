package cn.omisheep.authz.annotation;

import java.lang.annotation.*;

/**
 * @author zhou xin chen
 */
@Target({ElementType.PARAMETER, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Decrypt {
}
