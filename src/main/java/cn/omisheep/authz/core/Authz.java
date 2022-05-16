package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.AuthzDefender;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.util.AUtils;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class Authz {

    public static final PermissionDict permissionDict;
    public static final AuthzDefender auDefender;

    public static final UserDevicesDict userDevicesDict;
    public static final Cache cache;
    public static final Httpd httpd;

    static {
        permissionDict = PermissionDict.self();
        auDefender = AuthzDefender.self();

        userDevicesDict = AUtils.getBean(UserDevicesDict.class);
        cache = AUtils.getBean(Cache.class);
        httpd = AUtils.getBean(Httpd.class);
    }

}
