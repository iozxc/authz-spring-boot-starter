package cn.omisheep.authz.core.oauth;

import lombok.Data;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
public class AuthorizedDeviceDetails {
    private String clientId;
    private String clientName;

}
