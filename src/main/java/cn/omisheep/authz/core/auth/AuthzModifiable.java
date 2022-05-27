package cn.omisheep.authz.core.auth;

import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface AuthzModifiable {
    @Nullable
    Object modify(@NonNull AuthzModifier modifier);
}
