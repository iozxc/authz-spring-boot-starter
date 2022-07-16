package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.slot.SlotScan;
import cn.omisheep.authz.core.util.AUtils;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Import;

import java.nio.charset.StandardCharsets;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SlotScan("cn.omisheep.authz")
@Import({Httpd.class, PermissionDict.class, AUtils.class})
public class AuInit {

    public static final Logger log = LoggerFactory.getLogger(AuInit.class);

    public AuInit(AuthzProperties properties) {
        AuthzProperties.TokenConfig token = properties.getToken();
        if (token.getKey() == null || token.getKey().equals("")) {
            log.warn("token.key is empty, digital signature will not be executed, please configure in YML as soon as possible");
        } else {
            byte[]             keyBytes  = token.getKey().getBytes(StandardCharsets.UTF_8);
            SignatureAlgorithm algorithm = token.getAlgorithm();
            if (keyBytes.length * 8 < algorithm.getMinKeyLength()) {
                log.warn("The specified key byte array length is " + keyBytes.length + "，For the specified algorithm " + algorithm + " not safe enough. At least " + algorithm.getMinKeyLength() / 8 + " length, insufficient will default to `.` fill as `******..........................`，Please update the key as soon as possible");
            }
        }
    }

}
