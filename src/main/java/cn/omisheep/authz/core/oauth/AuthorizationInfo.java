package cn.omisheep.authz.core.oauth;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class AuthorizationInfo { //授权信息
    private String clientId;
    private String scope;
    private Object userId;
    private String deviceType;
    private String deviceId;
}
