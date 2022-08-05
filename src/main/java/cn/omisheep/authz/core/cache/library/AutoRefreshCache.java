package cn.omisheep.authz.core.cache.library;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.helper.BaseHelper;
import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.Async;
import org.aspectj.lang.ProceedingJoinPoint;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class AutoRefreshCache extends BaseHelper {

    static final ThreadLocal<Boolean> isLibrary = ThreadLocal.withInitial(() -> Boolean.FALSE);

    private static final ConcurrentHashMap<String, CompletableFuture<?>> refreshCache = new ConcurrentHashMap<>();

    public static boolean isLibrary() {
        return isLibrary.get();
    }

    public static void refresh(String key,
                               ProceedingJoinPoint joinPoint) {
        CompletableFuture<?> completableFuture = refreshCache.get(key);
        if (completableFuture != null) {
            LogUtils.debug("重复的刷新任务 key : {} ", key);
            if (Async.isSuccessFuture(completableFuture)) {
                refreshCache.remove(key);
            } else {
                LogUtils.debug("刷新任务未完成 key : {} ", key);
            }
        } else {
            HttpMeta currentHttpMeta = AuthzContext.getCurrentHttpMeta();
            CompletableFuture<Void> future = Async.run(() -> {
                try {
                    isLibrary.set(Boolean.TRUE);
                    AuthzContext.httpMeta.set(currentHttpMeta);
                    Object proceed = joinPoint.proceed();
                    cache.setSneaky(key, proceed);
                } catch (Throwable e) {
                    LogUtils.error(e);
                } finally {
                    isLibrary.set(Boolean.FALSE);
                }
            });
            refreshCache.put(key, future);
        }
    }
}
