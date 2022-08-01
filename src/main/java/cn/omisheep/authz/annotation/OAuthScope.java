package cn.omisheep.authz.annotation;

import cn.omisheep.authz.core.tk.GrantType;
import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface OAuthScope {

    /**
     * @return 需要的授权范围
     */
    @AliasFor("value")
    String[] scope() default {};

    /**
     * @return 需要的授权范围
     */
    @AliasFor("scope")
    String[] value() default {};

    /**
     * @return 能匹配上的认证类型
     */
    GrantType[] type() default {GrantType.AUTHORIZATION_CODE, GrantType.PASSWORD};

}
