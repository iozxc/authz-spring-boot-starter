package cn.omisheep.authz.core;

import cn.omisheep.authz.core.auth.PermFact;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import io.jsonwebtoken.lang.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Import;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Import({Httpd.class, PermissionDict.class, PermFact.class, AUtils.class})
public class AuInit {

    public static final Logger log = LoggerFactory.getLogger(AuInit.class);

    private final AuthzProperties properties;

    public AuInit(AuthzProperties properties) {
        this.properties = properties;

        Assert.notNull(this.properties.getToken().getKey(), "token配置异常,请在yml中配置key");

        initLogManager();
    }

    private void initLogManager() {
        LogUtils.setLogLevel(properties.getLog());
    }

}
