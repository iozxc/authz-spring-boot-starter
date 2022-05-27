package cn.omisheep.authz.core.init;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.slot.SlotScan;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import io.jsonwebtoken.lang.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Import;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SlotScan("cn.omisheep.authz")
@Import({Httpd.class, PermissionDict.class, AUtils.class})
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
