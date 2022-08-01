package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.annotation.OAuthScope;
import cn.omisheep.authz.annotation.OAuthScopeBasic;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.tk.GrantType;
import cn.omisheep.web.entity.Result;
import lombok.Data;
import lombok.Getter;
import lombok.experimental.Accessors;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.MetaUtils.*;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class OpenAuthDict {

    private static final Map<String, Map<String, OAuthInfo>> _src = new HashMap<>();

    @Data
    @Accessors(chain = true)
    public static class OAuthInfo {
        private Set<String>    scope;
        private Set<GrantType> type;
    }

    @Getter
    private static final Map<String, Map<String, OAuthInfo>> src = Collections.unmodifiableMap(_src);

    public static boolean target(String path,
                                 String method,
                                 GrantType type,
                                 Set<String> scope) {
        Map<String, OAuthInfo> p = src.get(path);
        if (p == null) return false;
        OAuthInfo authInfo = p.get(method);
        if (authInfo == null) return false;
        if (authInfo.scope == null || authInfo.scope.isEmpty()) {
            return false;
        }

        if (authInfo.type == null || authInfo.type.isEmpty()) {
            return false;
        }

        if (!authInfo.type.contains(type)) return false;
        return scope.containsAll(authInfo.scope);
    }

    public static void init(AuthzProperties properties,
                            ApplicationContext applicationContext,
                            Map<RequestMappingInfo, HandlerMethod> mapRet) {
        HashMap<String, Set<String>>    cMap              = new HashMap<>();
        HashMap<String, Set<GrantType>> gMap              = new HashMap<>();
        String                          defaultBasicScope = properties.getToken().getOauth().getDefaultBasicScope();

        applicationContext.getBeansWithAnnotation(OAuthScope.class).forEach((key, value) -> {
            String     name       = getTypeName(value);
            OAuthScope oAuthScope = getAnnotation(value, OAuthScope.class);
            if (oAuthScope == null) return;
            cMap.computeIfAbsent(name, r -> new HashSet<>()).addAll(Arrays.asList(oAuthScope.scope()));
            gMap.computeIfAbsent(name, r -> new HashSet<>()).addAll(Arrays.asList(oAuthScope.type()));
        });

        applicationContext.getBeansWithAnnotation(OAuthScopeBasic.class).forEach((key, value) -> {
            String          name            = getTypeName(value);
            OAuthScopeBasic oAuthScopeBasic = getAnnotation(value, OAuthScopeBasic.class);
            if (oAuthScopeBasic == null) return;
            Set<String> l = cMap.computeIfAbsent(name, r -> new HashSet<>());
            l.addAll(Arrays.asList(oAuthScopeBasic.scope()));
            l.add(defaultBasicScope);
            gMap.computeIfAbsent(name, r -> new HashSet<>()).addAll(Arrays.asList(oAuthScopeBasic.type()));
        });

        mapRet.forEach((key, value) -> {
            AtomicBoolean clientCredentials = new AtomicBoolean(false);
            List<String> mtds = key.getMethodsCondition().getMethods().stream().map(Enum::name).collect(
                    Collectors.toList());
            Set<String> patterns = getPatterns(key);
            HashSet<String> scope = new HashSet<>(
                    cMap.getOrDefault(value.getBeanType().getTypeName(), new HashSet<>())
            );
            HashSet<GrantType> type = new HashSet<>(
                    gMap.getOrDefault(value.getBeanType().getTypeName(), new HashSet<>())
            );

            OAuthScope oAuthScope = AnnotatedElementUtils.getMergedAnnotation(value.getMethod(), OAuthScope.class);
            if (oAuthScope != null) {
                scope.addAll(Arrays.asList(oAuthScope.scope()));
                type.addAll(Arrays.asList(oAuthScope.type()));
            }
            OAuthScopeBasic oAuthScopeBasic = AnnotatedElementUtils.getMergedAnnotation(value.getMethod(),
                                                                                        OAuthScopeBasic.class);
            if (oAuthScopeBasic != null) {
                scope.addAll(Arrays.asList(oAuthScopeBasic.scope()));
                scope.add(defaultBasicScope);
                type.addAll(Arrays.asList(oAuthScopeBasic.type()));
            }

            if (scope.isEmpty() && type.isEmpty()) return;
            patterns.forEach(pattern -> mtds.forEach(method -> {
                OAuthInfo authInfo = _src.computeIfAbsent(pattern, r -> new HashMap<>())
                        .computeIfAbsent(method, r -> new OAuthInfo());
                authInfo.scope = new HashSet<>();
                authInfo.type  = new HashSet<>();
                authInfo.scope.addAll(scope);
                authInfo.type.addAll(type);
            }));
        });
    }

    @Nullable
    public static Object modify(@NonNull AuthzModifier modifier) {
        if (modifier.getTarget() != AuthzModifier.Target.OPEN_AUTH) return Result.FAIL.data();
        switch (modifier.getOperate()) {
            case READ:
            case GET:
                return src;
            case ADD:
            case UPDATE:
            case MODIFY: {
                OAuthInfo oauth = modifier.getOauth();
                if (oauth == null) return Result.SUCCESS;
                _src.computeIfAbsent(modifier.getApi(), r -> new HashMap<>()).put(modifier.getMethod(), oauth);
                return Result.SUCCESS;
            }
            case DELETE:
            case DEL: {
                Map<String, OAuthInfo> map = _src.get(modifier.getApi());
                if (map != null) {
                    map.remove(modifier.getMethod());
                    if (map.isEmpty()) {
                        _src.remove(modifier.getApi());
                    }
                }
                return Result.SUCCESS;
            }
        }
        return Result.SUCCESS;
    }

}
