package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.annotation.OAuthScope;
import cn.omisheep.authz.annotation.OAuthScopeBasic;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.msg.AuthzModifier;
import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.MetaUtils.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class OpenAuthDict {

    private static final Map<String, Map<String, Set<String>>> _srcScope = new HashMap<>();

    @Getter
    private static final Map<String, Map<String, Set<String>>> srcScope = Collections.unmodifiableMap(_srcScope);

    @Nullable
    public Object modify(@NonNull AuthzModifier modifier) {
        return null;
    }

    public static boolean hasScope(String path, String method, Set<String> scope) {
        Map<String, Set<String>> p = _srcScope.get(path);
        if (p == null) return true;
        Set<String> requireScope = p.get(method);
        if (requireScope.isEmpty()) {
            return true;
        }
        if (scope.isEmpty()) return false;
        return scope.containsAll(requireScope);
    }

    public static void init(AuthzProperties properties, ApplicationContext applicationContext,
                            Map<RequestMappingInfo, HandlerMethod> mapRet) {
        HashMap<String, Set<String>> cMap              = new HashMap<>();
        String                       defaultBasicScope = properties.getToken().getOauth().getDefaultBasicScope();

        applicationContext.getBeansWithAnnotation(OAuthScope.class).forEach((key, value) -> {
            String     name       = getTypeName(value);
            OAuthScope oAuthScope = getAnnotation(value, OAuthScope.class);
            if (oAuthScope == null) return;
            cMap.computeIfAbsent(name, r -> new HashSet<>()).addAll(Arrays.asList(oAuthScope.scope()));
        });

        applicationContext.getBeansWithAnnotation(OAuthScopeBasic.class).forEach((key, value) -> {
            String          name            = getTypeName(value);
            OAuthScopeBasic oAuthScopeBasic = getAnnotation(value, OAuthScopeBasic.class);
            if (oAuthScopeBasic == null) return;
            Set<String> l = cMap.computeIfAbsent(name, r -> new HashSet<>());
            l.addAll(Arrays.asList(oAuthScopeBasic.scope()));
            l.add(defaultBasicScope);
        });

        mapRet.forEach((key, value) -> {
            List<String> mtds = key.getMethodsCondition().getMethods().stream().map(Enum::name).collect(
                    Collectors.toList());
            Set<String> patterns = getPatterns(key);
            HashSet<String> scope = new HashSet<>(
                    cMap.getOrDefault(value.getBeanType().getTypeName(), new HashSet<>())
            );
            OAuthScope oAuthScope = AnnotatedElementUtils.getMergedAnnotation(value.getMethod(), OAuthScope.class);
            if (oAuthScope != null) scope.addAll(Arrays.asList(oAuthScope.scope()));
            OAuthScopeBasic oAuthScopeBasic = AnnotatedElementUtils.getMergedAnnotation(value.getMethod(),
                                                                                        OAuthScopeBasic.class);
            if (oAuthScopeBasic != null) scope.addAll(Arrays.asList(oAuthScopeBasic.scope()));

            if (scope.isEmpty()) return;
            patterns.forEach(pattern -> mtds.forEach(method -> {
                _srcScope.computeIfAbsent(pattern, r -> new HashMap<>())
                        .computeIfAbsent(method, m -> new HashSet<>()).addAll(scope);
            }));
        });
    }

}
