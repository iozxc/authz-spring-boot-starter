package cn.omisheep.authz.core.cache.library;

import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.oauth.ClientDetails;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

import java.util.HashMap;
import java.util.List;

import static cn.omisheep.authz.core.config.Constants.AUTHORIZE_CODE_PREFIX;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Aspect
@SuppressWarnings("unchecked")
public class OpenAuthLibraryCache {
    private final Cache cache;


    public OpenAuthLibraryCache(Cache cache) {
        this.cache = cache;
    }

    @Around("execution(* cn.omisheep.authz.core.oauth.OpenAuthLibrary+.init())")
    public Object aroundInit(ProceedingJoinPoint joinPoint) throws Throwable {
        try {
            L2RefreshCacheSupport.isLibrary.set(Boolean.TRUE);
            List<ClientDetails>            initList = (List<ClientDetails>) joinPoint.proceed();
            HashMap<String, ClientDetails> map      = new HashMap<>(initList.size());
            for (ClientDetails clientDetails : initList) {
                map.put(Constants.CLINT_PREFIX.get() + clientDetails.getClientId(), clientDetails);
            }
            cache.set(map);
            return initList;
        } finally {
            L2RefreshCacheSupport.isLibrary.set(Boolean.FALSE);
        }

    }

    @Around("execution(* cn.omisheep.authz.core.oauth.OpenAuthLibrary+.getClientById(String))")
    public Object aroundGetClientById(ProceedingJoinPoint joinPoint) throws Throwable {
        String key = Constants.CLINT_PREFIX.get() + joinPoint.getArgs()[0];
        try {
            if (cache.notKey(key)) {
                L2RefreshCacheSupport.isLibrary.set(Boolean.TRUE);
                Object result = joinPoint.proceed();
                cache.set(key, result);
                return result;
            } else {
                return cache.get(key);
            }
        } finally {
            L2RefreshCacheSupport.isLibrary.set(Boolean.FALSE);
            L2RefreshCacheSupport.refresh(key, joinPoint);
        }
    }

    @Around("execution(* cn.omisheep.authz.core.oauth.OpenAuthLibrary+.deleteClientById(String))")
    public Object aroundDeleteClientById(ProceedingJoinPoint joinPoint) throws Throwable {
        try {
            cache.del(Constants.CLINT_PREFIX.get() + joinPoint.getArgs()[0]);
            L2RefreshCacheSupport.isLibrary.set(Boolean.TRUE);
            return joinPoint.proceed();
        } finally {
            L2RefreshCacheSupport.isLibrary.set(Boolean.FALSE);
        }

    }

    @Around("execution(* cn.omisheep.authz.core.oauth.OpenAuthLibrary+.registerClient(cn.omisheep.authz.core.oauth.ClientDetails)))")
    public Object aroundRegisterClient(ProceedingJoinPoint joinPoint) throws Throwable {
        try {
            L2RefreshCacheSupport.isLibrary.set(Boolean.TRUE);
            ClientDetails clientDetails = (ClientDetails) joinPoint.getArgs()[0];
            String        key           = Constants.CLINT_PREFIX.get() + clientDetails.getClientId();
            cache.set(key, clientDetails);
            return joinPoint.proceed();
        } finally {
            L2RefreshCacheSupport.isLibrary.set(Boolean.FALSE);
        }

    }

    @Around("execution(* cn.omisheep.authz.core.callback.AuthorizationCallback+.createAuthorizationCodeCallback(String,cn.omisheep.authz.core.oauth.AuthorizationInfo)))")
    public Object aroundCreateAuthorizationInfo(ProceedingJoinPoint joinPoint) throws Throwable {
        try {
            cache.set(AUTHORIZE_CODE_PREFIX.get() + joinPoint.getArgs()[0],
                      joinPoint.getArgs()[1],
                      AuthzAppVersion.AUTHORIZATION_CODE_TIME.get());
            L2RefreshCacheSupport.isLibrary.set(Boolean.TRUE);
            return joinPoint.proceed();
        } finally {
            L2RefreshCacheSupport.isLibrary.set(Boolean.FALSE);
        }

    }

}
