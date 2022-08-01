package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.util.AUtils;
import org.springframework.context.ApplicationContext;
/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@SuppressWarnings("rawtypes")
public abstract class BaseHelper {
    protected static final ApplicationContext ctx             = AUtils.getCtx();
    protected static final AuthzProperties    properties      = ctx.getBean(AuthzProperties.class);
    protected static final UserDevicesDict    userDevicesDict = ctx.getBean(UserDevicesDict.class);
    protected static final Cache              cache           = ctx.getBean("authzCache", Cache.class);
    protected static final PermLibrary        permLibrary     = ctx.getBean(PermLibrary.class);
}
