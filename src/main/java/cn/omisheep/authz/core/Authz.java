package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.AuthzModifier;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.AuthzDefender;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.cache.L2Cache;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.web.entity.Result;
import cn.omisheep.web.entity.ResultCode;
import org.springframework.lang.NonNull;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class Authz {

    public static final PermissionDict permissionDict;
    public static final AuthzDefender  auDefender;

    public static final UserDevicesDict userDevicesDict;
    public static final Cache           cache;
    public static final Httpd           httpd;

    static {
        permissionDict = PermissionDict.self();
        auDefender     = AuthzDefender.self();

        userDevicesDict = AUtils.getBean(UserDevicesDict.class);
        cache           = AUtils.getBean(Cache.class);
        httpd           = AUtils.getBean(Httpd.class);
    }

    public static Object op(@NonNull AuthzModifier authzModifier) {
        if (authzModifier.getTarget() == AuthzModifier.Target.RATE) {
            return httpd.modify(authzModifier);
        } else {
            return permissionDict.modify(authzModifier);
        }
    }

    public static Object modify(@NonNull AuthzModifier authzModifier) {
        try {
            return op(authzModifier);
        } finally {
            if (cache instanceof L2Cache) {
                VersionInfo.send(authzModifier);
            }
        }
    }

    public static Result operate(@NonNull AuthzModifier authzModifier) {
        Object modify = modify(authzModifier);
        if (modify instanceof Result) return (Result) modify;
        if (modify instanceof ResultCode) return ((ResultCode) modify).data();
        return Result.SUCCESS.data(modify);
    }



}
