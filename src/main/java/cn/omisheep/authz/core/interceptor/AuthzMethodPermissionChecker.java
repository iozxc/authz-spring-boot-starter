package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.PermissionException;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.commons.util.CollectionUtils;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.reflect.Method;
import java.util.*;

import static cn.omisheep.authz.core.util.MetaUtils.generatePermRolesMeta;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.10
 */
@Aspect
@SuppressWarnings("all")
public class AuthzMethodPermissionChecker {

    private final PermLibrary                    permLibrary;
    /**
     * 方法的Meta暂不支持修改。所以是固定的
     */
    private final HashMap<String, PermRolesMeta> prMeta = new HashMap<>();

    private final HashMap<String, Set<String>> scope = new HashMap<>();
    private final AuthzProperties              properties;

    public AuthzMethodPermissionChecker(PermLibrary permLibrary, AuthzProperties properties) {
        this.permLibrary = permLibrary;
        this.properties  = properties;
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.Roles)")
    public void hasRoles() {
    }

    @Pointcut("@within(cn.omisheep.authz.annotation.Roles)")
    public void hasRolesInType() {
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.Perms)")
    public void hasPerms() {
    }

    @Pointcut("@within(cn.omisheep.authz.annotation.Perms)")
    public void hasPermsInType() {
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.Certificated)")
    public void hasCertificated() {
    }

    @Pointcut("@within(cn.omisheep.authz.annotation.Certificated)")
    public void hasCertificatedInType() {
    }

    @Pointcut("@within(org.springframework.web.bind.annotation.RequestMapping)")
    public void hasRequestMapping() {
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.OAuthScope)")
    public void hasOAuthScope() {
    }

    @Pointcut("@within(cn.omisheep.authz.annotation.OAuthScope)")
    public void hasOAuthScopeInType() {
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.OAuthScopeBasic)")
    public void hasOAuthScopeBasic() {
    }

    @Pointcut("@within(cn.omisheep.authz.annotation.OAuthScopeBasic)")
    public void hasOAuthScopeBasicInType() {
    }

    @Before("!hasRequestMapping()&&(hasCertificated()||hasPerms()||hasRoles()||hasRolesInType()||hasPermsInType()||hasCertificatedInType())")
    public void checkPermissionAndRole(JoinPoint joinPoint) {
        try {
            MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
            Method method = joinPoint.getSignature().getDeclaringType().getMethod(joinPoint.getSignature().getName(),
                                                                                  methodSignature.getParameterTypes());
            Certificated mergedAnnotation = AnnotatedElementUtils.getMergedAnnotation(method, Certificated.class);
            Perms        perms            = AnnotatedElementUtils.getMergedAnnotation(method, Perms.class);
            Roles        roles            = AnnotatedElementUtils.getMergedAnnotation(method, Roles.class);

            Certificated mergedAnnotation2 = AnnotatedElementUtils.getMergedAnnotation(method.getDeclaringClass(),
                                                                                       Certificated.class);
            Perms perms2 = AnnotatedElementUtils.getMergedAnnotation(method.getDeclaringClass(), Perms.class);
            Roles roles2 = AnnotatedElementUtils.getMergedAnnotation(method.getDeclaringClass(), Roles.class);

            if (mergedAnnotation != null || roles != null || perms != null || mergedAnnotation2 != null || perms2 != null || roles2 != null) {
                if (!AuHelper.isLogin()) {
                    throw new NotLoginException();
                }
            }

            if (roles == null && perms == null && roles2 == null && perms2 == null) return;
            HttpMeta httpMeta = AuHelper.getHttpMeta();

            PermRolesMeta permRolesMeta = prMeta.computeIfAbsent(joinPoint.getSignature().toLongString(),
                                                                 r -> merge(perms, perms2, roles, roles2));
            if (permRolesMeta == null) return;
            Set<String> rolesByUserId = Optional.ofNullable(httpMeta.getRoles()).orElse(
                    permLibrary.getRolesByUserId(httpMeta.getUserId()));
            boolean e1 = CollectionUtils.isEmpty(permRolesMeta.getRequireRoles());
            boolean e2 = CollectionUtils.isEmpty(permRolesMeta.getExcludeRoles());
            if (!e1 && !CollectionUtils.containsSub(permRolesMeta.getRequireRoles(),
                                                    rolesByUserId) || !e2 && CollectionUtils.containsSub(
                    permRolesMeta.getExcludeRoles(), rolesByUserId)) {
                throw new PermissionException();
            }
            if (perms != null || perms2 != null) {
                Set<String> permissionsByRole = Optional.ofNullable(httpMeta.getPermissions()).orElseGet(() -> {
                    HashSet<String> p = new HashSet<>();
                    rolesByUserId.forEach(role -> p.addAll(permLibrary.getPermissionsByRole(role)));
                    return p;
                });
                boolean e3 = CollectionUtils.isEmpty(permRolesMeta.getRequireRoles());
                boolean e4 = CollectionUtils.isEmpty(permRolesMeta.getExcludeRoles());
                if (!e3 && !CollectionUtils.containsSub(permRolesMeta.getRequirePermissions(),
                                                        permissionsByRole) || !e4 && CollectionUtils.containsSub(
                        permRolesMeta.getExcludePermissions(), permissionsByRole)) {
                    throw new PermissionException();
                }
            }

        } catch (NoSuchMethodException e) {
            // skip
        }
    }

    @Before("!hasRequestMapping()&&(hasOAuthScope()||hasOAuthScopeInType()||hasOAuthScopeBasic()||hasOAuthScopeBasicInType())")
    public void checkScope(JoinPoint joinPoint) {
        try {
            Token token = AuHelper.getToken();
            if (token.getClientId() == null) return; //不需要拦截

            MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
            Method method = joinPoint.getSignature().getDeclaringType().getMethod(joinPoint.getSignature().getName(),
                                                                                  methodSignature.getParameterTypes());
            OAuthScope oAuthScope1 = AnnotatedElementUtils.getMergedAnnotation(method, OAuthScope.class);
            OAuthScope oAuthScope2 = AnnotatedElementUtils.getMergedAnnotation(method.getDeclaringClass(),
                                                                               OAuthScope.class);

            OAuthScopeBasic oAuthScopeBasic1 = AnnotatedElementUtils.getMergedAnnotation(method, OAuthScopeBasic.class);
            OAuthScopeBasic oAuthScopeBasic2 = AnnotatedElementUtils.getMergedAnnotation(method.getDeclaringClass(),
                                                                                         OAuthScopeBasic.class);

            Set<String> requireScope = scope.computeIfAbsent(joinPoint.getSignature().toLongString(), r ->
                    merge(oAuthScope1, oAuthScope2, oAuthScopeBasic1, oAuthScopeBasic1));
            if (requireScope.isEmpty()) return;
            if (token.getScope() == null
                    || !CollectionUtils.newSet(token.getScope().split(" ")).containsAll(requireScope)) {
                throw new PermissionException();
            }
        } catch (NoSuchMethodException e) {
            // skip
        }
    }


    private PermRolesMeta merge(Perms perms, Perms perms2, Roles roles, Roles roles2) {
        PermRolesMeta permRolesMeta1 = generatePermRolesMeta(perms, roles);
        PermRolesMeta permRolesMeta2 = generatePermRolesMeta(perms2, roles2);
        if (permRolesMeta1 != null && permRolesMeta2 == null) {
            return permRolesMeta1;
        }
        if (permRolesMeta1 == null && permRolesMeta2 != null) {
            return permRolesMeta2;
        }
        if (permRolesMeta1 != null && permRolesMeta2 != null) {
            // 合并
            Set<Set<String>> requirePermissions = permRolesMeta2.getRequirePermissions();
            if (requirePermissions != null) {
                if (permRolesMeta1.getRequirePermissions() != null) {
                    permRolesMeta1.getRequirePermissions().addAll(requirePermissions);
                } else {
                    permRolesMeta1.setRequirePermissions(requirePermissions);
                }
            }
            Set<Set<String>> requireRoles = permRolesMeta2.getRequireRoles();
            if (requirePermissions != null) {
                if (permRolesMeta1.getRequireRoles() != null) {
                    permRolesMeta1.getRequireRoles().addAll(requireRoles);
                } else {
                    permRolesMeta1.setRequireRoles(requireRoles);
                }
            }
            Set<Set<String>> excludePermissions = permRolesMeta2.getExcludePermissions();
            if (requirePermissions != null) {
                if (permRolesMeta1.getExcludePermissions() != null) {
                    permRolesMeta1.getExcludePermissions().addAll(excludePermissions);
                } else {
                    permRolesMeta1.setExcludePermissions(excludePermissions);
                }
            }
            Set<Set<String>> excludeRoles = permRolesMeta2.getExcludeRoles();
            if (requirePermissions != null) {
                if (permRolesMeta1.getExcludeRoles() != null) {
                    permRolesMeta1.getExcludeRoles().addAll(excludeRoles);
                } else {
                    permRolesMeta1.setExcludeRoles(excludeRoles);
                }
            }
            return permRolesMeta1;
        }
        return null;
    }

    private Set<String> merge(OAuthScope oAuthScope1, OAuthScope oAuthScope2, OAuthScopeBasic oAuthScopeBasic1,
                              OAuthScopeBasic oAuthScopeBasic2) {
        HashSet<String> set = new HashSet<>();
        if (oAuthScopeBasic1 != null || oAuthScopeBasic2 != null) {
            String defaultScope = properties.getToken().getOauth().getDefaultScope();
            if (defaultScope != null) {
                set.addAll(Arrays.asList(defaultScope.split(" ")));
            }
        }
        if (oAuthScope1 != null) {
            set.addAll(Arrays.asList(oAuthScope1.scope()));
        }
        if (oAuthScope2 != null) {
            set.addAll(Arrays.asList(oAuthScope2.scope()));
        }
        if (oAuthScopeBasic1 != null) {
            set.addAll(Arrays.asList(oAuthScopeBasic1.scope()));
        }
        if (oAuthScopeBasic2 != null) {
            set.addAll(Arrays.asList(oAuthScopeBasic2.scope()));
        }
        return set;
    }


}
