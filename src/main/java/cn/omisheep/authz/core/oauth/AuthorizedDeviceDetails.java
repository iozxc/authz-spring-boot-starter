package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.tk.GrantType;
import lombok.Data;

import java.util.Date;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
public class AuthorizedDeviceDetails {
    private String    authorizedDeviceId;
    private Object    userId;
    private String    clientId;
    private GrantType grantType;
    private String    scope;
    private Date      authorizedDate;
    private Date      expiresDate;

    public AuthorizedDeviceDetails(Device device,
                                   Object userId,
                                   String authorizedDeviceId) {
        this.authorizedDeviceId             = authorizedDeviceId;
        this.userId         = userId;
        this.clientId       = device.getClientId();
        this.grantType      = device.getGrantType();
        this.scope          = device.getScope();
        this.authorizedDate = device.getAuthorizedDate();
        this.expiresDate    = device.getExpiresDate();
    }

    public AuthorizedDeviceDetails(AuthorizationInfo authorizationInfo,
                                   String authorizedDeviceId) {
        this.userId    = authorizationInfo.getUserId();
        this.clientId  = authorizationInfo.getClientId();
        this.grantType = authorizationInfo.getGrantType();
        this.scope     = authorizationInfo.getScope();
        if (authorizationInfo.getAuthorizedAt() != null) {
            this.authorizedDate = new Date(authorizationInfo.getAuthorizedAt());
        }
        if (authorizationInfo.getExpiresAt() != null) {
            this.expiresDate = new Date(authorizationInfo.getExpiresAt());
        }
        this.authorizedDeviceId = authorizedDeviceId;
    }
}
