package cn.omisheep.authz.annotation;

import cn.omisheep.authz.core.config.AuthzResourcesInit;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import(AuthzResourcesInit.class)
public @interface AuthzResourcesScan {

    @AliasFor("entityBasePackages")
    String[] entity() default {};

    @AliasFor("entity")
    String[] entityBasePackages() default {};

    @AliasFor("argsBasePackages")
    String[] args() default {};

    @AliasFor("args")
    String[] argsBasePackages() default {};

}
