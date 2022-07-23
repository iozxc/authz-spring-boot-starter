package cn.omisheep.authz.support.http.annotation;

import cn.omisheep.authz.support.http.ApiSupportImport;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import(ApiSupportImport.class)
public @interface ApiSupportScan {
    @AliasFor("packages")
    String[] value() default {};

    @AliasFor("value")
    String[] packages() default {};
}
