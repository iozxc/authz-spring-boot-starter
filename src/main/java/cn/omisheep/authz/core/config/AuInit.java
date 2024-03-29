package cn.omisheep.authz.core.config;

import cn.omisheep.authz.annotation.AuthzResourcesScan;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.slot.SlotScan;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SlotScan("cn.omisheep.authz")
@AuthzResourcesScan(args = "cn.omisheep.authz.core.auth.ipf.HttpMeta")
public class AuInit {

    public static final Logger log = LoggerFactory.getLogger(AuInit.class);

    public AuInit(AuthzProperties properties) {
        AuthzProperties.TokenConfig token = properties.getToken();
        if (token.getKey() == null || token.getKey().equals("")) {
            log.warn(
                    "token.key is empty, digital signature will not be executed, please configure in YML as soon as possible");
        } else {
            byte[] keyBytes = token.getKey().getBytes(StandardCharsets.UTF_8);
            if (keyBytes.length * 8 < SignatureAlgorithm.HS256.getMinKeyLength()) {
                log.warn(
                        "The specified key byte array length is " + keyBytes.length + "，For the specified algorithm HS256 not safe enough. At least " + SignatureAlgorithm.HS256.getMinKeyLength() / 8 + " length, insufficient will default to `.` fill as `******..........................`，Please update the key as soon as possible");
            }
        }
    }

}
