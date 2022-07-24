package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.annotation.Certificated;
import cn.omisheep.authz.annotation.Perms;
import cn.omisheep.authz.annotation.Roles;
import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.PermissionException;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.commons.util.CollectionUtils;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static cn.omisheep.authz.core.util.MetaUtils.generatePermRolesMeta;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.10
 */
@Aspect
@Slf4j
@SuppressWarnings("all")
public class AuthzMethodPermissionChecker {

    private final PermLibrary                    permLibrary;
    private final HashMap<String, PermRolesMeta> meta = new HashMap<>();

    public AuthzMethodPermissionChecker(PermLibrary permLibrary) {
        this.permLibrary = permLibrary;
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.Roles)")
    public void hasRoles() {
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.Perms)")
    public void hasPerms() {
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.Certificated)")
    public void hasCertificated() {
    }

    @Pointcut("@within(org.springframework.web.bind.annotation.RequestMapping)")
    public void hasRequestMapping() {
    }

    @Before("!hasRequestMapping() && (hasCertificated()||hasPerms()||hasRoles()) ")
    public void around(JoinPoint joinPoint) {
        try {
            MethodSignature methodSignature  = (MethodSignature) joinPoint.getSignature();
            Method          method           = joinPoint.getSignature().getDeclaringType().getMethod(joinPoint.getSignature().getName(), methodSignature.getParameterTypes());
            Certificated    mergedAnnotation = AnnotatedElementUtils.getMergedAnnotation(method, Certificated.class);
            Perms           perms            = AnnotatedElementUtils.getMergedAnnotation(method, Perms.class);
            Roles           roles            = AnnotatedElementUtils.getMergedAnnotation(method, Roles.class);
            PermRolesMeta   permRolesMeta    = meta.computeIfAbsent(joinPoint.getSignature().toLongString(), r -> generatePermRolesMeta(perms, roles));
            HttpMeta        httpMeta         = AuHelper.getHttpMeta();
            if (mergedAnnotation != null || roles != null || perms != null) {
                if (!AuHelper.isLogin()) {
                    throw new NotLoginException();
                }
            }
            if (roles != null || perms != null) {
                Set<String> rolesByUserId = Optional.ofNullable(httpMeta.getRoles()).orElse(permLibrary.getRolesByUserId(httpMeta.getUserId()));
                if (!CollectionUtils.containsSub(permRolesMeta.getRequireRoles(), rolesByUserId) ||
                        CollectionUtils.containsSub(permRolesMeta.getExcludeRoles(), rolesByUserId)) {
                    throw new PermissionException();
                }
                if (perms != null) {
                    Set<String> permissionsByRole = Optional.ofNullable(httpMeta.getPermissions()).orElseGet(() -> {
                        HashSet<String> p = new HashSet<>();
                        rolesByUserId.forEach(role -> p.addAll(permLibrary.getPermissionsByRole(role)));
                        return p;
                    });
                    if (!CollectionUtils.containsSub(permRolesMeta.getRequirePermissions(), permissionsByRole) ||
                            CollectionUtils.containsSub(permRolesMeta.getExcludePermissions(), permissionsByRole)) {
                        throw new PermissionException();
                    }
                }
            }
        } catch (NoSuchMethodException e) {
            // skip
        }
    }

}
