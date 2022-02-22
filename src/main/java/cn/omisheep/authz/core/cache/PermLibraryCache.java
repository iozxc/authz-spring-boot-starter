package cn.omisheep.authz.core.cache;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 2022-02-03
 */
@Aspect
@Slf4j
public class PermLibraryCache {

    private final Cache cache;

    public PermLibraryCache(Cache cache) {
        this.cache = cache;
    }

    @Around("execution(* cn.omisheep.authz.PermLibrary+.getRolesByUserId(..))")
    public Object Before(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        if (args.length != 1) return joinPoint.proceed();
        return handle("userRoles:" + args[0], joinPoint);
    }

    @Around("execution(* cn.omisheep.authz.PermLibrary+.getPermissionsByRole(..))")
    public Object Before2(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Class<?>[] parameterTypes = methodSignature.getParameterTypes();
        if (parameterTypes.length != 1 || parameterTypes[0] != String.class) return joinPoint.proceed();
        return handle("permissionsByRole:" + args[0], joinPoint);
    }

    @Around("execution(* cn.omisheep.authz.PermLibrary+.getPermissionsByUserId(..))")
    public Object Before3(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        if (args.length != 1) return joinPoint.proceed();
        return handle("permissionsByUserId:" + args[0], joinPoint);
    }

    private Object handle(String key, ProceedingJoinPoint joinPoint) throws Throwable {
        System.out.println("handle");
        Object o = cache.get(key);
        if (o != null) return o;
        if (!cache.hasKey(key)) {
            Object result = joinPoint.proceed();
            cache.set(key, result);
            return result;
        }
        return null;
    }

}
