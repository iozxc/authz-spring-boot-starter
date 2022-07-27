package cn.omisheep.authz.core.cache.library;

import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

import java.util.HashSet;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Aspect
public class PermLibraryCache {

    private final Cache cache;

    public PermLibraryCache(Cache cache) {
        this.cache = cache;
    }

    @Around("execution(* cn.omisheep.authz.core.auth.PermLibrary+.getRolesByUserId(..))")
    public Object aroundRolesByUserId(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        if (args.length != 1) return joinPoint.proceed();
        return handle(Constants.USER_ROLES_KEY_PREFIX.get() + args[0], joinPoint);
    }

    @Around("execution(* cn.omisheep.authz.core.auth.PermLibrary+.getPermissionsByRole(String))")
    public Object aroundPermissionsByRole(ProceedingJoinPoint joinPoint) throws Throwable {
        return handle(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX.get() + joinPoint.getArgs()[0], joinPoint);
    }

    private Object handle(String key, ProceedingJoinPoint joinPoint) throws Throwable {
        Object o = cache.get(key);
        if (o != null) return o;
        Object result = joinPoint.proceed();
        if (result == null) {
            HashSet<String> set = new HashSet<>();
            cache.set(key, set);
            return set;
        }
        cache.set(key, result);
        return result;
    }

}
