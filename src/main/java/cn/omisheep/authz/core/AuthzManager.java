package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.L2Cache;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.helper.BaseHelper;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.oauth.OpenAuthDict;
import cn.omisheep.web.entity.ResponseResult;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuthzManager extends BaseHelper {

    private AuthzManager() {
        throw new UnsupportedOperationException();
    }

    @Nullable
    public static Object op(@NonNull AuthzModifier authzModifier) {
        try {
            switch (authzModifier.getTarget()) {
                case OPEN_AUTH:
                    return OpenAuthDict.modify(authzModifier);
                case RATE:
                    return Httpd.modify(authzModifier);
                case BLACKLIST:
                    return Blacklist.modify(authzModifier);
                default:
                    return PermissionDict.modify(authzModifier);
            }
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }
    }

    @Nullable
    public static Object modify(@NonNull AuthzModifier authzModifier) {
        try {
            return op(authzModifier);
        } finally {
            if (cache instanceof L2Cache) AuthzAppVersion.send(authzModifier);
        }
    }

    @NonNull
    public static ResponseResult<?> operate(@NonNull AuthzModifier authzModifier) {
        Object res = modify(authzModifier);
        if (res == null) return AuthzResult.SUCCESS.data(null);
        if (res instanceof ResponseResult) return (ResponseResult<?>) res;
        if (res instanceof AuthzResult) return ((AuthzResult) res).data();
        return AuthzResult.SUCCESS.data(res);
    }

}
