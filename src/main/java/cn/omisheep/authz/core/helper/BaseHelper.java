package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.util.AUtils;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@SuppressWarnings("rawtypes")
public abstract class BaseHelper {
    protected static final AuthzProperties properties      = AUtils.getBean(AuthzProperties.class);
    public static final    UserDevicesDict userDevicesDict = AUtils.getBean(UserDevicesDict.class);
    public static final    Cache           cache           = AUtils.getBean(Cache.class);
    public static final    PermLibrary     permLibrary     = AUtils.getBean(PermLibrary.class);
}
