package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.tk.GrantType;

import java.util.Date;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface Device extends Map<Object, Object>, java.io.Serializable {

    // 设备id
    String getDeviceId();

    Device setDeviceId(String id);

    // 设备类型
    String getDeviceType();

    Device setDeviceType(String type);

    // accessTokenId
    String getAccessTokenId();

    Device setAccessTokenId(String accessTokenId);

    // scope
    String getScope();

    Device setScope(String scope);

    // grantType
    GrantType getGrantType();

    Device setGrantType(GrantType grantType);

    // clientId
    String getClientId();

    Device setClientId(String clientId);

    // clientId
    Date getAuthorizedDate();

    Device setAuthorizedDate(Date authorizedDate);

    // 过期时间
    Date getExpiresDate();

    Device setExpiresDate(Date expiresDate);

    // 绑定的ip
    String getBindIp();

    Device setBindIp(String ip);

}
