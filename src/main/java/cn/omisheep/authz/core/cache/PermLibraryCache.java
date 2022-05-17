package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.core.Constants;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;

import java.util.HashSet;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Aspect
@Slf4j
public class PermLibraryCache {

    private final Cache cache;

    public PermLibraryCache(Cache cache) {
        this.cache = cache;
    }

    @Around("execution(* cn.omisheep.authz.core.auth.PermLibrary+.getRolesByUserId(..))")
    public Object Before(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        if (args.length != 1) return joinPoint.proceed();
        return handle(Constants.USER_ROLES_KEY_PREFIX + args[0], joinPoint);
    }

    @Around("execution(* cn.omisheep.authz.core.auth.PermLibrary+.getPermissionsByRole(..))")
    public Object Before2(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[]        args            = joinPoint.getArgs();
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Class<?>[]      parameterTypes  = methodSignature.getParameterTypes();
        if (parameterTypes.length != 1 || parameterTypes[0] != String.class) return joinPoint.proceed();
        return handle(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX + args[0], joinPoint);
    }

    private Object handle(String key, ProceedingJoinPoint joinPoint) throws Throwable {
        Object o = cache.get(key);
        if (o != null) return o;
        if (cache.notKey(key)) {
            Object result = joinPoint.proceed();
            cache.set(key, result, Cache.INFINITE);
            if (result == null) return new HashSet<String>();
            return result;
        }
        return new HashSet<String>();
    }

}
