package cn.omisheep.authz.core.auth.deviced;


import cn.omisheep.authz.core.tk.GrantType;

import static cn.omisheep.authz.core.config.Constants.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
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
    public Long getExpiresAt() {
        return getLong(ACCESS_TOKEN_EXPIRATION);
    }

    @Override
    public Device setExpiresAt(Long accessExpiresAt) {
        setValue(ACCESS_TOKEN_EXPIRATION, String.valueOf(accessExpiresAt));
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

}
