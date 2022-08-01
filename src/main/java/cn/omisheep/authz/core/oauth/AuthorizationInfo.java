package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.core.tk.GrantType;
import lombok.Data;
import lombok.experimental.Accessors;

/**
 * 授权信息
 *
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class AuthorizationInfo {
    private final String    clientId;
    private final String    clientName;
    private final String    scope;
    private final GrantType grantType;
    private final Long      expiresIn;
    private final Long      expiresAt;
    private final Long      authorizedAt;
    private final Object    userId;
}
