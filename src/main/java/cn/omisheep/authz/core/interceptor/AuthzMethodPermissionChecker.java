package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.*;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.oauth.OpenAuthDict;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.tk.GrantType;
import cn.omisheep.commons.util.CollectionUtils;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

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
    private final HashMap<String, Boolean>       cMeta  = new HashMap<>();

    private final HashMap<String, OpenAuthDict.OAuthInfo> oauthInfoList = new HashMap<>();
    private final AuthzProperties                         properties;

    public AuthzMethodPermissionChecker(PermLibrary permLibrary,
                                        AuthzProperties properties) {
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
            String name = joinPoint.getSignature().toLongString();

            AtomicReference<Set<Auth>>         auths         = new AtomicReference<>();
            AtomicReference<Set<Certificated>> certificateds = new AtomicReference<>();

            Boolean requireLogin = cMeta.computeIfAbsent(name, r -> {
                certificateds.set(AnnotatedElementUtils.getAllMergedAnnotations(method,
                                                                                Certificated.class));
                auths.set(AnnotatedElementUtils.getAllMergedAnnotations(method.getDeclaringClass(),
                                                                        Auth.class));
                return !auths.get().isEmpty() || !certificateds.get().isEmpty();
            });

            if (!requireLogin) return;

            if (!AuHelper.isLogin()) {
                throw new NotLoginException();
            }

            PermRolesMeta permRolesMeta = prMeta.computeIfAbsent(joinPoint.getSignature().toLongString(), r -> {
                if (auths.get() == null) {
                    auths.set(AnnotatedElementUtils.getAllMergedAnnotations(method.getDeclaringClass(), Auth.class));
                }
                return generatePermRolesMeta(auths.get());
            });

            if (permRolesMeta == null) return;

            HttpMeta    httpMeta      = AuHelper.getHttpMeta();
            Set<String> rolesByUserId = httpMeta.getRoles();

            if (permRolesMeta.getRoles() != null) {
                if (!CollectionUtils.containsSub(permRolesMeta.getRequireRoles(), rolesByUserId)
                        || CollectionUtils.containsSub(permRolesMeta.getExcludeRoles(), rolesByUserId)) {
                    throw new PermissionException();
                }
            }

            if (permRolesMeta.getPermissions() != null) {
                Set<String> permissionsByRole = httpMeta.getPermissions();
                if (!CollectionUtils.containsSub(permRolesMeta.getRequirePermissions(), permissionsByRole)
                        || CollectionUtils.containsSub(permRolesMeta.getExcludePermissions(), permissionsByRole)) {
                    throw new PermissionException();
                }
            }

        } catch (NoSuchMethodException e) {
            // skip
        }
    }

    @Before("!hasRequestMapping()&&(hasOAuthScope()||hasOAuthScopeInType()||hasOAuthScopeBasic()||hasOAuthScopeBasicInType())")
    public void checkScope(JoinPoint joinPoint) { // todo
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Method          method          = null;
        try {
            method = joinPoint.getSignature().getDeclaringType().getMethod(joinPoint.getSignature().getName(),
                                                                           methodSignature.getParameterTypes());
        } catch (NoSuchMethodException e) {
            // skip
        }
        if (method == null) return;

        AccessToken accessToken = AuHelper.getToken();
        if (accessToken == null) {
            throw new NotLoginException();
        }
        if (accessToken.getClientId() == null) return; //不需要拦截
        if (AuHelper.getHttpMeta().getScope().isEmpty() || AuHelper.getHttpMeta()
                .getToken()
                .getGrantType() == null) {
            throw new AuthzException(ExceptionStatus.SCOPE_EXCEPTION_OR_TYPE_ERROR);
        }

        OAuthScope oAuthScope1 = AnnotatedElementUtils.getMergedAnnotation(method, OAuthScope.class);
        OAuthScope oAuthScope2 = AnnotatedElementUtils.getMergedAnnotation(method.getDeclaringClass(),
                                                                           OAuthScope.class);

        OAuthScopeBasic oAuthScopeBasic1 = AnnotatedElementUtils.getMergedAnnotation(method, OAuthScopeBasic.class);
        OAuthScopeBasic oAuthScopeBasic2 = AnnotatedElementUtils.getMergedAnnotation(method.getDeclaringClass(),
                                                                                     OAuthScopeBasic.class);

        OpenAuthDict.OAuthInfo oAuthInfo = oauthInfoList
                .computeIfAbsent(joinPoint.getSignature().toLongString(),
                                 r -> merge(oAuthScope1, oAuthScope2,
                                            oAuthScopeBasic1,
                                            oAuthScopeBasic1));

        if (oAuthInfo == null) return;
        if (!oAuthInfo.getType().contains(accessToken.getGrantType())) {
            throw new AuthzException(ExceptionStatus.SCOPE_EXCEPTION_OR_TYPE_ERROR);
        }
        if (!AuHelper.getHttpMeta().getScope().containsAll(oAuthInfo.getScope())) {
            throw new AuthzException(ExceptionStatus.SCOPE_EXCEPTION_OR_TYPE_ERROR);
        }

    }

    private OpenAuthDict.OAuthInfo merge(OAuthScope oAuthScope1,
                                         OAuthScope oAuthScope2,
                                         OAuthScopeBasic oAuthScopeBasic1,
                                         OAuthScopeBasic oAuthScopeBasic2) {
        HashSet<String>    set  = new HashSet<>();
        HashSet<GrantType> set2 = new HashSet<>();
        if (oAuthScopeBasic1 != null || oAuthScopeBasic2 != null) {
            String defaultScope = properties.getToken().getOauth().getDefaultBasicScope();
            if (defaultScope != null) {
                set.addAll(Arrays.asList(defaultScope.split(" ")));
            }
        }
        if (oAuthScope1 != null) {
            set.addAll(Arrays.asList(oAuthScope1.scope()));
            set2.addAll(Arrays.asList(oAuthScope1.type()));
        }
        if (oAuthScope2 != null) {
            set.addAll(Arrays.asList(oAuthScope2.scope()));
            set2.addAll(Arrays.asList(oAuthScope2.type()));
        }
        if (oAuthScopeBasic1 != null) {
            set.addAll(Arrays.asList(oAuthScopeBasic1.scope()));
            set2.addAll(Arrays.asList(oAuthScopeBasic1.type()));
        }
        if (oAuthScopeBasic2 != null) {
            set.addAll(Arrays.asList(oAuthScopeBasic2.scope()));
            set2.addAll(Arrays.asList(oAuthScopeBasic2.type()));
        }

        if (set.isEmpty() || set2.isEmpty()) return null;
        return new OpenAuthDict.OAuthInfo().setScope(set).setType(set2);
    }

}
