package cn.omisheep.authz.core.auth.deviced;


import cn.omisheep.authz.core.tk.GrantType;

import java.util.Date;

import static cn.omisheep.authz.core.config.Constants.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.2.0
 * @since 1.0.0
 */
public class DefaultDevice extends AuthzMap implements Device {
    private static final long serialVersionUID = 3561879223319144385L;

    public DefaultDevice() {
        super();
    }

    @Override
    public String getDeviceType() {
        return getString(DEVICE_TYPE);
    }

    @Override
    public Device setDeviceType(String type) {
        setValue(DEVICE_TYPE, type);
        return this;
    }

    @Override
    public String getDeviceId() {
        return getString(DEVICE_ID);
    }

    @Override
    public Device setDeviceId(String id) {
        setValue(DEVICE_ID, id);
        return this;
    }

    @Override
    public String getAccessTokenId() {
        return getString(ACCESS_TOKEN_ID);
    }

    @Override
    public Device setAccessTokenId(String accessTokenId) {
        setValue(ACCESS_TOKEN_ID, accessTokenId);
        return this;
    }

    @Override
    public String getScope() {
        return getString(SCOPE);
    }

    @Override
    public Device setScope(String scope) {
        setValue(SCOPE, scope);
        return this;
    }

    @Override
    public GrantType getGrantType() {
        return GrantType.grantType(getString(GRANT_TYPE));
    }

    @Override
    public Device setGrantType(GrantType grantType) {
        setValue(GRANT_TYPE, grantType.getType());
        return this;
    }

    @Override
    public String getClientId() {
        return getString(CLIENT_ID);
    }

    @Override
    public Device setClientId(String clientId) {
        setValue(CLIENT_ID, clientId);
        return this;
    }

    @Override
    public Date getAuthorizedDate() {
        return getDate(AUTHORIZED_TIME);
    }

    @Override
    public Device setAuthorizedDate(Date authorizedDate) {
        setDate(AUTHORIZED_TIME, authorizedDate);
        return this;
    }

    @Override
    public Date getExpiresDate() {
        return getDate(EXPIRES_TIME);
    }

    @Override
    public Device setExpiresDate(Date expiresDate) {
        setDate(EXPIRES_TIME, expiresDate);
        return this;
    }

    @Override
    public String getBindIp() {
        return getString(BIND_IP);
    }

    @Override
    public Device setBindIp(String ip) {
        setValue(BIND_IP, ip);
        return this;
    }

}
