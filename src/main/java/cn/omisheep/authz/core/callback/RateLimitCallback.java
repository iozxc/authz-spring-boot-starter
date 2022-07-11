package cn.omisheep.authz.core.callback;

import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.Date;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.1
 */
@FunctionalInterface
@SuppressWarnings("all")
public interface RateLimitCallback {
    void forbid(@NonNull String method,
                @NonNull String api,
                @Nullable String ip,
                @Nullable Object userId,
                @NonNull LimitMeta limitMeta,
                @NonNull Date reliveDate);

    default void relive(@NonNull String method,
                        @NonNull String api,
                        @Nullable String ip,
                        @Nullable Object userId,
                        @NonNull LimitMeta limitMeta) {
    }
}
