package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.annotation.OAuthScope;
import cn.omisheep.authz.annotation.OAuthScopeBasic;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.msg.AuthzModifier;
import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class OpenAuthDict {

    private static final Map<String, Map<String, List<String>>> _srcScope = new HashMap<>();

    @Getter
    private static final Map<String, Map<String, List<String>>> srcScope = Collections.unmodifiableMap(_srcScope);

    @Nullable
    public Object modify(@NonNull AuthzModifier modifier) {
        return null;
    }

    public static void init(AuthzProperties properties,
                            ApplicationContext applicationContext,
                            PermLibrary permLibrary,
                            Cache cache,
                            Map<RequestMappingInfo, HandlerMethod> mapRet){
        applicationContext.getBeansWithAnnotation(OAuthScope.class).forEach((key, value) -> {
            System.out.println(key);
            System.out.println(value);
        });

        applicationContext.getBeansWithAnnotation(OAuthScopeBasic.class).forEach((key, value) -> {
            System.out.println(key);
            System.out.println(value);
        });

    }
}
